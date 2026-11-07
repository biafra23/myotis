# roost: the light-client server

*Stop 20 · standalone crate `roost`* · 8 files · 5,722 lines · about 135 minutes

A daemon that the project runs itself. It pulls light-client objects from a local Nimbus beacon node over loopback REST, keeps them in a durable archive plus an in-memory cache of *pre-encoded* responses, and serves them to wallets over `myotis-net`'s own libp2p stack. This is the carve-out in your CLAUDE.md: roost relays *self-verifying* objects and never has to be trusted, because every wallet checks every update against sync-committee signatures. Rust-wise it's a textbook async *application*: `#[tokio::main]`, `anyhow`, one `select!` loop, and very little shared state.

## Rust you will practise

- **An application, not a library** — `#[tokio::main]`, `anyhow::Result` with context, typed errors only where callers branch on them.
- **Minimal sharing** — state confined to one task; `Arc<LcStore>` with a `std::sync::RwLock`; lock poisoning under `panic = "unwind"`.
- **Bytes you don't trust** — panic-free parsing with `get`, `checked_add`, `let … else`, and an append-only file format.

> [!TIP]
> **What changed since September**
>
> Little, and all of it at the edges. `participation_of` in `main.rs` now picks the Gloas or pre-Gloas decoder by length, so Gloas periods are judged instead of reading as undecodable. `serve.rs` sets three new `HostConfig` fields (`listen_quic`, `cl_fork_watch`, `traffic`) to `None`. The codec, protocol names and fork-digest arithmetic roost imports from `myotis_net::{codec, protocols, status}` now live in `myotis-wire` ([Stop 5](05-wire.md)); `myotis-net` re-exports them at the old paths, so roost's imports did not change. The other six files are byte-for-byte the same.

![roost's task layout. The main serve task fetches SSZ from Nimbus over loopback REST on a 12 second tick, appends to the archive file, and writes pre-encoded responses into a shared Arc LcStore and the status into an Arc LocalStatus. The libp2p swarm task from myotis-net answers wallets by reading the store synchronously and queues bootstrap misses that the main task later drains. The main task also watches the swarm task's JoinHandle and exits if it ends.](img/20-roost-1.svg)

*Only two objects are shared between tasks, and both sit behind `Arc` plus a `std` lock. Everything else the daemon changes (the archive, digests, the ENR sequence, the external address) is a plain local of the main task. The swarm answers from bytes that were encoded in advance and never waits for ingestion: a miss answers `ResourceUnavailable` and is filled on a later tick.*

<a id="f-roost-src-main-rs"></a>

### roost/src/main.rs

*binary · crate root · 921 lines*

Declares the modules, parses the command line by hand, and dispatches to four commands: `probe` (read-only upstream diagnostics), `ingest` (fill the archive without listening), `serve` (the daemon) and `enr` (print the ENR it would publish). It also holds the pure rules for “is this stored update provisional?” and `find_window_floor`, which the daemon reuses. Every error is an `anyhow::Error`.

`rust/roost/src/main.rs` · lines 12–33

```rust
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

mod archive;
mod enr;
mod forks;
mod framing;
mod rest;
mod serve;
mod store;

use archive::Archive;
use framing::{split_updates, updates_to_wire};
use rest::NimbusRest;
use store::LcStore;

const DEFAULT_REST: &str = "http://127.0.0.1:5052";
const DEFAULT_ARCHIVE: &str = "roost-archive.db";
const DEFAULT_PORT: u16 = 9105;

```

`rust/roost/src/main.rs` · lines 62–69

```rust
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
```

`rust/roost/src/main.rs` · lines 97–110

```rust
"--port" => {
    i += 1;
    port = args
        .get(i)
        .ok_or_else(|| anyhow!("--port needs a number\n\n{}", usage()))?
        .parse::<u16>()
        .ok()
        // Zero is a valid u16 but not a valid listen port here: it
        // asks the OS for an ephemeral one, and the daemon would
        // then advertise `/tcp/0`, which nothing can dial. Reject it
        // rather than print an unusable multiaddr.
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow!("--port must be a number 1-65535\n\n{}", usage()))?;
}
```

`rust/roost/src/main.rs` · lines 137–148

```rust
    match command.as_deref() {
        Some("probe") => probe(&rest_base).await,
        Some("ingest") => ingest(&rest_base, &archive_path).await,
        Some("serve") => serve::serve(&rest_base, &archive_path, key_path, port, publish_enr).await,
        Some("enr") => show_enr(&rest_base, &archive_path, key_path, advertise, port).await,
        Some(other) => Err(anyhow!("unknown command '{other}'\n\n{}", usage())),
        None => {
            print!("{}", usage());
            Ok(())
        }
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Binaries, CLIs & signals](01-primer.md#primer-cli)* **`#[tokio::main]`** turns `async fn main` into a plain `main` that builds a multi-threaded runtime (a work-stealing pool, like `ForkJoinPool`) and `block_on`s the body. When `main` returns, the runtime is dropped, and so are any tasks still running.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **`anyhow` in a binary.** `Result<T>` here means `Result<T, anyhow::Error>`: any error plus a chain of context, like a Java `Exception` with causes. `?` converts any standard error type automatically. `myotis-net`'s `Result<_, String>` needs `.map_err(|e| anyhow!("{e}"))`, because `String` isn't an error type. If `main` returns `Err`, the process prints it and exits with status 1.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **An `Option` chain** for `--port`: the bounds-checked `get(i)`, then `ok_or_else` + `?`, then `parse().ok()`, then `filter` (rejects 0), then `ok_or_else` + `?`. Each step either continues or produces a helpful error.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* `command.as_deref()` turns `Option<String>` into `Option<&str>`, so string literals work as patterns without moving `command`. `key_path` is moved in *two* arms, which compiles because only one arm ever runs: moves are tracked per control-flow path.

`rust/roost/src/main.rs` · lines 564–584

```rust

/// Sync-aggregate participant count of an SSZ-encoded `LightClientUpdate`, or
/// `None` when it does not decode with this build's (fork-polymorphic) decoder.
/// Used by ingest to judge whether a stored update is provisional.
///
/// A Gloas update is fixed-size and no pre-Gloas update has that length, so
/// the length alone picks its decoder here. (A wallet goes by the chunk's
/// context bytes instead; roost only needs the participant count, and without
/// this every Gloas period would read as undecodable — stored once and never
/// replaced by a better copy.)
pub(crate) fn participation_of(ssz: &[u8]) -> Option<usize> {
    use myotis_consensus::{fork::LcFork, types::LightClientUpdate};
    let fork = if ssz.len() == LightClientUpdate::GLOAS_SIZE {
        LcFork::Gloas
    } else {
        LcFork::PreGloas
    };
    LightClientUpdate::decode_for(fork, ssz)
        .ok()
        .map(|u| u.sync_aggregate.count_participants())
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Choosing a decoder by length.** At the Gloas fork the light-client header changed shape: it now carries only the execution block hash, and the whole update has a fixed size, `LightClientUpdate::GLOAS_SIZE`. A wallet picks the decoder from the chunk's context bytes. roost only needs the participant count, so it uses the fact the doc comment states: no pre-Gloas update has that length. `let fork = if … { LcFork::Gloas } else { LcFork::PreGloas };` is an `if` used as an expression, like Kotlin's. `decode_for(fork, ssz)` returns a `Result`; `.ok()` discards the error, and `.map(…)` reaches into the decoded update only on success. The decoded value is a temporary, dropped at the end of the statement once its count has been read. Before this change every Gloas period decoded as `None`, so `should_replace` below would have frozen the first copy ever stored.

`rust/roost/src/main.rs` · lines 586–613

```rust
/// Below the light-client supermajority bar — a wallet REFUSES such an update,
/// so serving one stalls every catch-up through its period.
pub(crate) fn below_supermajority(participants: usize) -> bool {
    participants * 3 < myotis_consensus::spec::SYNC_COMMITTEE_SIZE * 2
}

/// Whether ingest must refetch a period from upstream instead of freezing what
/// it holds: not held at all; still in progress (upstream's by-range answer is
/// its best update SEEN SO FAR, improving as the period ages); stored below
/// the supermajority; or stored undecodable by this build (`stored == None`
/// while held — a record nobody with this decoder can use). Pure — every
/// promised ingest property is pinned by the table tests below.
pub(crate) fn needs_refetch(held: bool, stored: Option<usize>, in_progress: bool) -> bool {
    !held || in_progress || stored.is_none_or(below_supermajority)
}

/// Whether a fresh chunk replaces a held record: strictly more participants;
/// a decodable update beats an undecodable stored one; an undecodable fresh
/// chunk never replaces anything (it cannot be judged). Strictly-better-only
/// is what makes repeated ingests idempotent — equal copies are never
/// re-appended. Pure — pinned by the table tests below.
pub(crate) fn should_replace(stored: Option<usize>, fresh: Option<usize>) -> bool {
    match (stored, fresh) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(old), Some(new)) => new > old,
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* Pure rules with table tests. A wallet refuses an update signed by fewer than ⅔ of the 512-member committee (342 is the lowest acceptable count), so `ingest` refetches a period that isn't held, is still in progress, is stored below that bar, or can't be decoded. `stored.is_none_or(below_supermajority)` passes a *function* where a closure is expected. `should_replace` accepts only strictly more participants, which makes a rerun idempotent. `pub(crate)` exposes them to `serve.rs` only.

`rust/roost/src/main.rs` · lines 819–837

```rust
async fn find_window_floor(client: &NimbusRest, head_period: u64) -> Result<Option<u64>> {
    let has = |p: u64| async move {
        Ok::<bool, anyhow::Error>(!client.updates(p, 1).await?.bytes.is_empty())
    };

    if !has(head_period).await? {
        return Ok(None);
    }
    let (mut lo, mut hi) = (0u64, head_period); // hi always has data
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if has(mid).await? {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(Some(lo))
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `has` is a closure that *returns a future*. Each call creates a new, lazy future holding `p` and a reference to `client`, and nothing runs until it is awaited.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `Ok::<bool, anyhow::Error>(…)`: an async block can't declare its return type, so without the turbofish the `?` inside wouldn't know which error type to convert into.
- *[Protocol & domain](01-primer.md#primer-domain)* A binary search for the lowest period Nimbus still serves, which assumes the servable window has no gaps.

<a id="f-roost-src-rest-rs"></a>

### roost/src/rest.rs

*binary · 769 lines*

roost's only upstream: an async client for Nimbus's beacon REST API. REST bypasses Nimbus's libp2p peer table and connection semaphore entirely. The four light-client endpoints are fetched as SSZ (`Accept: application/octet-stream`), so roost stays a byte cache that relays exactly what Nimbus produced. The JSON endpoints cover head and finality, `config/spec`, the genesis root, peers and addresses.

`rust/roost/src/rest.rs` · lines 43–58

```rust
/// Silently is the operative word: every period number roost computes rests on
/// this, including the keys its **archive records are written under**. A wrong
/// value does not fail — it mis-keys durable data, and the archive is the one
/// thing here that cannot be regenerated.
/// Fields are PRIVATE so [`ChainParams::from_spec`] is the only way in. They
/// were `pub`, which meant `ChainParams { slots_per_epoch: 0, .. }` compiled and
/// divided by zero in `period_of_slot` — unwinding out of `serve`'s main task,
/// not a per-connection one. "Refuse anything unusable" is only a contract if
/// the unusable value cannot be built at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    /// Validated once, at construction — see `from_spec`.
    slots_per_period: u64,
}
```

`rust/roost/src/rest.rs` · lines 88–119

```rust
pub fn from_spec(spec: &std::collections::BTreeMap<String, String>) -> Result<Self> {
    let read = |key: &str| -> Result<u64> {
        let raw = spec
            .get(key)
            .ok_or_else(|| anyhow!("config/spec has no {key}"))?;
        let v: u64 = raw.parse().with_context(|| format!("parsing {key} = {raw}"))?;
        if v == 0 {
            return Err(anyhow!("config/spec reports {key} = 0"));
        }
        Ok(v)
    };
    let slots_per_epoch = read("SLOTS_PER_EPOCH")?;
    let epochs_per_sync_committee_period = read("EPOCHS_PER_SYNC_COMMITTEE_PERIOD")?;
    // checked, not saturating: a saturating product answers u64::MAX, which
    // makes period_of_slot answer 0 for every real slot — so every archive
    // record would be written under period 0. Silently mis-keying
    // unregenerable data is the exact failure this type exists to prevent,
    // and saturation would have reintroduced it.
    let slots_per_period = slots_per_epoch
        .checked_mul(epochs_per_sync_committee_period)
        .ok_or_else(|| {
            anyhow!(
                "config/spec geometry overflows u64: {slots_per_epoch} x \
                 {epochs_per_sync_committee_period}"
            )
        })?;
    Ok(Self {
        slots_per_epoch,
        epochs_per_sync_committee_period,
        slots_per_period,
    })
}
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Result, ? and panics](01-primer.md#primer-error-handling)* **A smart constructor through privacy.** The fields are private, so other modules can't write `ChainParams { slots_per_epoch: 0, .. }`, and `from_spec`, which refuses missing, zero or overflowing values, is the only way in. The doc records the bug this prevents: with `pub` fields, a zero compiled and later divided by zero. It's the Java private-fields-plus-static-factory idiom, enforced by the compiler. `Copy` makes it a small value type.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `checked_mul`, not saturating: a saturated product would make every period number 0 and silently mis-key the irreplaceable archive. `read` is a closure that borrows `spec` and declares `-> Result<u64>`, so `?` works inside it.

`rust/roost/src/rest.rs` · lines 143–167

```rust
/// Why a fetch failed, split by whether retrying could ever help.
///
/// The distinction is load-bearing for bootstraps: a root is marked attempted
/// BEFORE the fetch, so treating a timeout like a 404 would permanently poison a
/// wallet's pinned checkpoint on one upstream hiccup.
#[derive(Debug)]
pub enum FetchError {
    /// The upstream answered, and its answer means "I do not have this" — 4xx.
    /// Retrying is pointless.
    Unavailable(u16),
    /// Timeout, connection failure, 5xx, oversized or unreadable body. The same
    /// request may well succeed later.
    Transient(anyhow::Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(code) => write!(f, "upstream does not have it (HTTP {code})"),
            Self::Transient(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for FetchError {}
```

`rust/roost/src/rest.rs` · lines 225–269

```rust
let status = resp.status();
let consensus_version = resp
    .headers()
    .get("eth-consensus-version")
    .and_then(|v| v.to_str().ok())
    .map(str::to_string);

if !status.is_success() {
    // 408 and 429 are 4xx but RETRYABLE, and treating them as definitive
    // poisons a root permanently: `take_bootstrap_misses` marks it
    // attempted before this request and only `Transient` is requeued, so
    // one rate-limit answer makes every later wallet retry return
    // ResourceUnavailable forever. The Unavailable/Transient split exists
    // precisely to keep a temporary condition from becoming permanent.
    let retryable = matches!(status.as_u16(), 408 | 429);
    return Err(if status.is_client_error() && !retryable {
        FetchError::Unavailable(status.as_u16())
    } else {
        FetchError::Transient(anyhow!("GET {url} -> HTTP {status}"))
    });
}

// A declared Content-Length over the cap is refused before a byte of
// body is read; a chunked response without one is caught below.
if let Some(len) = resp.content_length() {
    if len > MAX_BODY_BYTES as u64 {
        return Err(FetchError::Transient(anyhow!(
            "GET {url}: declared body {len} exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})"
        )));
    }
}

let mut bytes: Vec<u8> = Vec::new();
while let Some(chunk) = resp
    .chunk()
    .await
    .map_err(|e| FetchError::Transient(anyhow!("reading body of {url}: {e}")))?
{
    if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
        return Err(FetchError::Transient(anyhow!(
            "GET {url}: body exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})"
        )));
    }
    bytes.extend_from_slice(&chunk);
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Typed errors where a caller branches.** `anyhow` is fine for failures that are only reported. `FetchError` exists because `serve.rs` must *decide*: requeue a `Transient` bootstrap, or give up on an `Unavailable` one. A variant wrapping `anyhow::Error` keeps the message chain. `impl std::error::Error for FetchError {}` is empty because every method has a default, and it lets `?` convert the error into `anyhow`.
- *[Protocol & domain](01-primer.md#primer-domain)* HTTP 408 and 429 are 4xx codes but retryable. Treating them as “unavailable” would mark a wallet's pinned checkpoint as permanently refused after a single rate-limit answer.
- *[async/await & tokio](01-primer.md#primer-async) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `while let Some(chunk) = resp.chunk().await…?` is the async version of an `InputStream.read` loop. A chunked response has no `Content-Length`, so the 32 MiB cap is enforced as the data arrives. `&chunk` deref-coerces from `&Bytes` to `&[u8]`. `.map(str::to_string)` uses a method path as a function.
- *[async/await & tokio](01-primer.md#primer-async)* `async fn get_ssz(&self, …)` returns a future that borrows `self`, and nothing is sent until it's awaited, unlike an eager `CompletableFuture`. There is no retry code at all: the 12-second tick simply runs failed work again.

<a id="f-roost-src-store-rs"></a>

### roost/src/store.rs

*binary · 672 lines*

The in-memory serving cache that the libp2p responder reads. It holds *fully encoded* libp2p responses (`result || digest || varint || snappy`), so serving is a lookup plus a copy, and compression happens once, at ingest. It also bounds bootstrap handling: a FIFO-evicted cache, a queue of misses for the background filler, and a record of roots already attempted.

`rust/roost/src/store.rs` · lines 12–24

```rust
//! # Synchronous by requirement, not by preference
//!
//! `respond_inbound` in `myotis-net` is **synchronous**, called inline from
//! `on_rr_event` on the single swarm task — there is no `await` point. So this
//! is a `std::sync::RwLock`, never a `tokio::sync::RwLock`: an async lock could
//! not be taken there, and an on-demand fetch inside the handler would either
//! stall every other connection's handshakes for an HTTP round trip or
//! `block_on` inside a tokio worker and panic.
//!
//! The consequence is the design's item 4: **the handler is a pure cache read,
//! and a miss stays `ResourceUnavailable`**, with a background task filling it.
//! That is correct behaviour — a wallet retries against another peer and the
//! second attempt hits — and it preserves the broadcast-cache property.
```

`rust/roost/src/store.rs` · lines 102–141

```rust
/// Shared, cheap to clone, safe to read from the swarm task.
#[derive(Debug, Default)]
pub struct LcStore {
    inner: RwLock<Inner>,
}

/// A snapshot of what the store can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub lowest_period: Option<u64>,
    pub highest_period: Option<u64>,
    pub periods: usize,
    pub bootstraps: usize,
    pub has_finality: bool,
    pub has_optimistic: bool,
    pub update_bytes: usize,
}

impl LcStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock accessors that IGNORE poisoning.
    ///
    /// A panic while one of these locks is held would otherwise poison it and
    /// make every later `unwrap()` panic too — so a single panic anywhere on
    /// the swarm task would convert this store into one that refuses forever.
    /// Nothing here has an invariant a torn write can break in a way a reader
    /// would misinterpret: the maps hold immutable pre-encoded byte blobs, and
    /// the worst case is a bootstrap present in the map but missing from the
    /// eviction queue, which costs one extra entry. Serving stale-but-valid
    /// bytes beats serving nothing.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [async/await & tokio](01-primer.md#primer-async)* **Why a `std` lock.** `respond_inbound` in `myotis-net` is synchronous and runs inline on the single swarm task. An async lock can't be awaited there, and a `block_on` inside a runtime worker would panic. So: `std::sync::RwLock`, and no method ever returns a guard, so none can be held across an `.await`.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Poisoning is real here.** roost unwinds on panic, so a panic while the lock is held *poisons* it, and every later `read().unwrap()` would panic too. `unwrap_or_else(|e| e.into_inner())` takes the guard anyway, which is justified because the entries are immutable byte blobs: “serving stale-but-valid bytes beats serving nothing”. Java has no equivalent; `finally { unlock(); }` just releases the lock. (The “cheap to clone” doc is stale: `LcStore` isn't `Clone`; it's shared through `Arc`.)
- *[Lifetimes](01-primer.md#primer-lifetimes)* `RwLockReadGuard<'_, Inner>`: the guard borrows `self`, and `'_` lets the compiler infer the lifetime.

`rust/roost/src/store.rs` · lines 152–173

```rust
pub fn update_ssz(&self, period: u64) -> Option<Vec<u8>> {
    let wire = self.read().updates.get(&period).cloned()?;
    decode_multi_chunk_response(&wire, 1)
        .ok()?
        .into_iter()
        .next()
}

pub fn insert_update(&self, period: u64, fork_digest: [u8; 4], ssz: &[u8]) {
    let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
    let mut inner = self.write();
    let newest = inner.updates.keys().next_back().copied();
    if newest.is_none_or(|n| period >= n) {
        inner.newest_fork_digest = Some(fork_digest);
    }
    inner.updates.insert(period, wire);
}

pub fn set_finality(&self, fork_digest: [u8; 4], ssz: &[u8]) {
    let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
    self.write().finality = Some(wire);
}
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Temporaries die at the `;`.** `self.read().updates.get(&period).cloned()?` drops the read guard at the end of that statement, before the slow snappy decode. `self.write().finality = Some(wire);` is a one-statement critical section. `Arc<[u8]>` is an immutable, reference-counted slice in one allocation, and cloning it only bumps the count, like sharing a Java reference to an immutable `byte[]`. The encoding happens *before* the lock is taken. (The doc on lines 145–147 describes `insert_update` but is attached to `update_ssz`.)

`rust/roost/src/store.rs` · lines 240–278

```rust
pub fn clear_bootstraps(&self) -> usize {
    let mut inner = self.write();
    let dropped = inner.bootstraps.len();
    for root in inner.bootstrap_order.clone() {
        inner.bootstrap_attempted.remove(&root);
        inner.bootstrap_attempted_order.retain(|r| r != &root);
    }
    inner.bootstraps.clear();
    inner.bootstrap_order.clear();
    dropped
}

/// Queue a root for the background filler. Returns false when the queue is
/// full or the root was already attempted — both mean "do not fetch".
pub fn record_bootstrap_miss(&self, root: [u8; 32]) -> bool {
    // Read-lock first. This runs on the swarm task for EVERY miss, so a
    // caller spamming unknown roots must not be able to serialise the
    // responder behind a write lock it will not end up needing.
    {
        let inner = self.read();
        if inner.bootstrap_attempted.contains(&root)
            || inner.bootstrap_miss_set.contains(&root)
            || inner.bootstrap_misses.len() >= MAX_BOOTSTRAP_MISSES
        {
            return false;
        }
    }
    let mut inner = self.write();
    // Re-check: the lock was released in between.
    if inner.bootstrap_attempted.contains(&root)
        || inner.bootstrap_miss_set.contains(&root)
        || inner.bootstrap_misses.len() >= MAX_BOOTSTRAP_MISSES
    {
        return false;
    }
    inner.bootstrap_misses.push_back(root);
    inner.bootstrap_miss_set.insert(root);
    true
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Read first, then write, then re-check.** This runs on the swarm task for every miss, so the common “nothing to do” case needs only a shared lock. The inner `{ }` drops the read guard before the write lock is requested: `std`'s `RwLock` can't upgrade, and asking for the write lock while holding the read lock on the same thread can deadlock or panic. The state may change in the gap, hence the second check.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Interior mutability](01-primer.md#primer-interior-mutability)* **A clone that satisfies the borrow checker.** In `clear_bootstraps`, both field accesses go through the same guard (`Deref`/`DerefMut`). Iterating `inner.bootstrap_order` while calling `inner.bootstrap_attempted.remove` looks to the compiler like a shared and a mutable borrow of `inner` at once, so it rejects it. Cloning at most 64 roots avoids that; reborrowing `let i = &mut *inner;` would allow disjoint field borrows instead.

`rust/roost/src/store.rs` · lines 331–368

```rust
pub fn updates_range(&self, start_period: u64, count: u64) -> Option<Vec<u8>> {
    if count == 0 || count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
        return None;
    }
    let inner = self.read();

    // Refuse out-of-window rather than scanning for it.
    let (&lowest, _) = inner.updates.iter().next()?;
    let (&highest, _) = inner.updates.iter().next_back()?;
    if start_period < lowest || start_period > highest {
        return None;
    }

    let mut out = Vec::new();
    let mut served = 0u64;
    // Walked with a checked increment rather than `start..start+count`:
    // `saturating_add` would make the range EMPTY at `u64::MAX` instead of
    // one element long, silently turning a servable period into a miss.
    let mut period = start_period;
    for _ in 0..count {
        let Some(chunk) = inner.updates.get(&period) else {
            break; // contiguity ends; answer with what we have
        };
        if out.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            break;
        }
        out.extend_from_slice(chunk);
        served += 1;
        match period.checked_add(1) {
            Some(next) => period = next,
            None => break, // end of the number line, not an error
        }
    }
    if served == 0 {
        return None;
    }
    Some(out)
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* The hot path. A caller controls `start` and `count` (both `u64`), so everything is bounded: at most 128 updates, 8 MiB in total, nothing outside the held window, and a stop at the first gap. `let (&lowest, _) = inner.updates.iter().next()?;` destructures a reference in a pattern and uses `?` on an `Option`. `period.checked_add(1)` avoids overflow at `u64::MAX`, and a partial run is a legitimate answer.

`rust/roost/src/store.rs` · lines 412–436

```rust
/// The seam `myotis-net`'s swarm calls into.
///
/// Every method is a pure read of what ingestion already encoded — no I/O, no
/// allocation beyond the response copy, no await. That is a hard requirement,
/// not a style choice: this runs inline on the single swarm task, so anything
/// blocking here stalls every other connection's handshakes and responses.
impl myotis_net::reqresp::LcResponder for LcStore {
    fn bootstrap(&self, block_root: &[u8; 32]) -> Option<Vec<u8>> {
        match LcStore::bootstrap(self, block_root) {
            Some(b) => Some(b.to_vec()),
            None => {
                // Miss: queue it and answer ResourceUnavailable. The wallet
                // retries, and the retry hits. Still no I/O on this task.
                if self.record_bootstrap_miss(*block_root) {
                    tracing::info!(root = %hex::encode(&block_root[..8]),
                        "bootstrap miss queued for background fetch");
                }
                None
            }
        }
    }

    fn updates_by_range(&self, start_period: u64, count: u64) -> Option<Vec<u8>> {
        self.updates_range(start_period, count)
    }
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **Implementing another crate's trait.** The orphan rule allows it because `LcStore` is local. The trait is `Send + Sync`, which holds automatically because `RwLock<Inner>` is. Both the inherent method and the trait method are called `bootstrap`; `LcStore::bootstrap(self, …)` picks the inherent one (which returns an `Arc`). A miss queues the root and answers `None` (`ResourceUnavailable`), and the wallet's retry hits.

<a id="f-roost-src-archive-rs"></a>

### roost/src/archive.rs

*binary · 542 lines*

A durable, append-only file of per-period `LightClientUpdate` SSZ plus fork digest. Periods below Nimbus's light-client floor can never be regenerated, so this file is irreplaceable. On load it checks the header (magic, version, chain id), verifies an FNV-1a checksum per record, repairs a torn tail by truncating it, and scans past corrupt regions to save the records after them. It stores raw SSZ, so a codec change never invalidates it.

`rust/roost/src/archive.rs` · lines 91–130

```rust
/// Append-only archive file.
#[derive(Debug)]
pub struct Archive {
    path: PathBuf,
    file: File,
}

impl Archive {
    /// Open (or create) the archive and load every intact record.
    ///
    /// `genesis_validators_root` identifies the chain. An archive built for one
    /// network must never load for another — the updates would be verified
    /// against the wrong sync committee and rejected by every wallet, which is
    /// a confusing way to discover you copied the wrong file. Same role the
    /// watch-list fingerprint plays for the log index.
    pub fn open(
        path: impl AsRef<Path>,
        genesis_validators_root: &[u8; 32],
    ) -> Result<(Self, BTreeMap<u64, ArchivedUpdate>, LoadReport)> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;

        let len = file.metadata()?.len();
        if len == 0 {
            write_header(&mut file, genesis_validators_root)?;
            return Ok((Self { path, file }, BTreeMap::new(), LoadReport::default()));
        }
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Ownership instead of locking.** `append(&mut self)` requires exclusive access, so the compiler guarantees a single writer. Only `serve`'s main task holds `mut archive`: no `Mutex`, no `Arc`. Dropping the `Archive` closes the file, like an automatic try-with-resources.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `path: impl AsRef<Path>` accepts `&Path`, `PathBuf` or `&str`. The tuple return value is destructured by callers: `let (mut archive, records, report) = Archive::open(…)?;`.

`rust/roost/src/archive.rs` · lines 165–197

```rust
/// Append one period. Never rewrites, so this cannot damage what is already
/// stored — the worst an interrupted call can do is leave a torn tail that
/// the next [`Archive::open`] truncates.
pub fn append(&mut self, period: u64, fork_digest: [u8; 4], ssz: &[u8]) -> Result<()> {
    if ssz.len() > MAX_RECORD_SSZ {
        bail!(
            "period {period}: {} SSZ bytes exceeds MAX_RECORD_SSZ ({MAX_RECORD_SSZ})",
            ssz.len()
        );
    }
    let mut body = Vec::with_capacity(ssz.len() + 32);
    body.extend_from_slice(REC_MAGIC);
    body.push(KIND_UPDATE);
    body.extend_from_slice(&period.to_le_bytes());
    body.extend_from_slice(&fork_digest);
    body.extend_from_slice(&(ssz.len() as u32).to_le_bytes());
    body.extend_from_slice(ssz);
    let checksum = fnv64(&body);
    body.extend_from_slice(&checksum.to_le_bytes());

    self.file
        .write_all(&body)
        .with_context(|| format!("appending period {period} to {}", self.path.display()))?;
    Ok(())
}

/// Flush and fsync. Called per batch rather than per record: 1327 periods is
/// one bulk collection, and a torn tail is recoverable by construction.
pub fn flush(&mut self) -> Result<()> {
    self.file.flush()?;
    self.file.sync_data()?;
    Ok(())
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* `bail!(…)` is shorthand for `return Err(anyhow!(…))`. A record is `RREC | kind | period (u64 LE) | digest | len (u32 LE) | ssz | fnv64`, built in memory and written with a single `write_all`. `flush` runs `sync_data` (fdatasync) once per batch; a torn tail is recoverable by design. There is no OS file lock, so nothing stops two processes from appending to the same file.

`rust/roost/src/archive.rs` · lines 294–342

```rust
enum RecordRead {
    Ok { record: ArchivedUpdate, next: usize },
    Torn,
    Corrupt,
}

fn read_record(buf: &[u8], pos: usize) -> RecordRead {
    // rec_magic(4) + kind(1) + period(8) + digest(4) + ssz_len(4) = 21
    const FIXED: usize = 4 + 1 + 8 + 4 + 4;
    let Some(head) = buf.get(pos..pos.saturating_add(FIXED)) else {
        return RecordRead::Torn;
    };
    if &head[..4] != REC_MAGIC {
        return RecordRead::Corrupt;
    }
    if head[4] != KIND_UPDATE {
        return RecordRead::Corrupt;
    }
    let period = u64::from_le_bytes(head[5..13].try_into().unwrap());
    let mut fork_digest = [0u8; 4];
    fork_digest.copy_from_slice(&head[13..17]);
    let ssz_len = u32::from_le_bytes(head[17..21].try_into().unwrap()) as usize;
    if ssz_len == 0 || ssz_len > MAX_RECORD_SSZ {
        return RecordRead::Corrupt;
    }

    let Some(body_end) = pos.checked_add(FIXED).and_then(|p| p.checked_add(ssz_len)) else {
        return RecordRead::Corrupt;
    };
    let Some(ssz) = buf.get(pos + FIXED..body_end) else {
        return RecordRead::Torn;
    };
    let Some(sum_bytes) = buf.get(body_end..body_end.saturating_add(8)) else {
        return RecordRead::Torn;
    };
    let stored = u64::from_le_bytes(sum_bytes.try_into().unwrap());
    if fnv64(&buf[pos..body_end]) != stored {
        return RecordRead::Corrupt;
    }

    RecordRead::Ok {
        record: ArchivedUpdate {
            period,
            fork_digest,
            ssz: ssz.to_vec(),
        },
        next: body_end + 8,
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **A data-carrying enum.** `RecordRead::Ok { record, next }` has fields; `Torn` and `Corrupt` don't. Elsewhere, `if let RecordRead::Ok { .. } = …` ignores the fields.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Panic-free parsing.** `buf.get(a..b)` returns `None` where `buf[a..b]` would panic. Arithmetic overflow means *corrupt*; running out of bytes means *torn*. Both are plain values. `try_into().unwrap()` is used only on slices whose length was just checked. `ssz` is borrowed from the file buffer and copied with `to_vec()` only once the checksum matches.
- *[Protocol & domain](01-primer.md#primer-domain)* A corrupted length field in the middle of the file looks exactly like a torn tail, so `parse` first checks whether an intact record follows. Without that check it would truncate, and delete, irreplaceable records.

<a id="f-roost-src-forks-rs"></a>

### roost/src/forks.rs

*binary · 744 lines*

Computes the 4-byte fork digest (“context bytes”) for any slot, and the 16-byte `ENRForkID`, from the chain's own `/eth/v1/config/spec`. A name→digest table won't do: since EIP-7892 the digest also mixes in the active blob parameters, so one fork name can have several digests. Forks are discovered from key names (`X_FORK_VERSION` + `X_FORK_EPOCH`). The arithmetic is `myotis_net::status::fork_digest_bpo`, the twin of Java's `BeaconLightClient.computeForkDigest`. Since the September tour that function lives in `myotis-wire`'s `eth2::status`; `myotis-net`'s `status` module is now a one-line `pub use` of it.

`rust/roost/src/forks.rs` · lines 18–23

````rust
//! So it is computed, per the spec:
//!
//! ```text
//! fork_digest = (fork_data_root(fork_version, gvr)
//!                XOR sha256(u64_le(bpo_epoch) || u64_le(max_blobs)))[0..4]
//! ```
````

`rust/roost/src/forks.rs` · lines 88–97

```rust
pub async fn fetch_with_params(
    client: &NimbusRest,
    genesis_validators_root: [u8; 32],
) -> Result<(ChainParams, Result<Self>)> {
    let (spec, blobs) = client.config_spec().await?;
    let params = ChainParams::from_spec(&spec)?;
    let schedule = Self::from_spec(&spec, genesis_validators_root, params)
        .map(|s| s.with_blob_schedule(blobs).with_implicit_electra_blobs(&spec));
    Ok((params, schedule))
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling)* **Two failure policies in one return type.** The outer `?`s are fatal (a failed fetch, unusable geometry). The inner `Result<Self>` is returned as a *value*, so the caller can fall back to the digest it observed on the wire.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Ownership & moves](01-primer.md#primer-ownership)* `Result::map` takes an `FnOnce`, which runs at most once, so the closure may *move* the captured `blobs` vector. It only borrows `spec`. `params` is used twice because `ChainParams` is `Copy`.

`rust/roost/src/forks.rs` · lines 182–221

```rust
/// Attach the `BLOB_SCHEDULE` array, which `config/spec` returns as objects
/// rather than scalars and so arrives separately.
pub fn with_blob_schedule(mut self, mut entries: Vec<BlobParams>) -> Self {
    entries.sort_by_key(|b| b.epoch);
    self.blob_schedule = entries;
    self
}

/// Fold in the blob parameters Electra set, which are NOT in `BLOB_SCHEDULE`.
///
/// EIP-7892's schedule lists the parameters a chain has CHANGED to; it does
/// not restate the ones the Electra fork already established. On mainnet and
/// sepolia that distinction is invisible, because both have explicit later
/// entries that win the `rfind` anyway. On GNOSIS it is the whole answer:
/// `BLOB_SCHEDULE` is `[]`, so reading the schedule alone concluded "no BPO
/// active", roost stamped the bare Fulu digest `f9ab5f85`, and every peer
/// answered `Goodbye(IrrelevantNetwork)` — the server was live, reachable
/// and invisible.
///
/// The wire is what proved it: the observed digest `3237dab6` is exactly
/// `fulu_base XOR sha256(le(1337856) || le(2))`, i.e. `ELECTRA_FORK_EPOCH`
/// and `MAX_BLOBS_PER_BLOCK_ELECTRA`.
///
/// Added as an ordinary entry rather than a special case, so `rfind` keeps
/// being the single rule: an explicit later entry still wins, an empty
/// schedule now has a floor. Absent keys are left alone — a pre-Electra
/// chain legitimately has neither.
pub fn with_implicit_electra_blobs(mut self, spec: &BTreeMap<String, String>) -> Self {
    let epoch = spec.get("ELECTRA_FORK_EPOCH").and_then(|v| v.parse::<u64>().ok());
    let max_blobs = spec
        .get("MAX_BLOBS_PER_BLOCK_ELECTRA")
        .and_then(|v| v.parse::<u64>().ok());
    if let (Some(epoch), Some(max_blobs)) = (epoch, max_blobs) {
        if !self.blob_schedule.iter().any(|b| b.epoch == epoch) {
            self.blob_schedule.push(BlobParams { epoch, max_blobs });
            self.blob_schedule.sort_by_key(|b| b.epoch);
        }
    }
    self
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Consuming builders.** `fn with_blob_schedule(mut self, …) -> Self` takes ownership, changes the value and returns it, with nothing copied. Java “withers” usually copy. That's what makes `from_spec(..)?.with_…(..).with_…(..)` chains work.
- *[Protocol & domain](01-primer.md#primer-domain)* **The Gnosis lesson.** Gnosis's `BLOB_SCHEDULE` is empty, so roost stamped the bare Fulu digest, and every peer answered `Goodbye(IrrelevantNetwork)`: the server was live, reachable and invisible. The implicit Electra entry fixed it. A wrong digest costs reachability, never correctness.

`rust/roost/src/forks.rs` · lines 228–238

```rust
/// The fork active at `epoch` — the latest whose activation is not in the
/// future. Forks scheduled at `u64::MAX` (a placeholder for "not scheduled",
/// e.g. GLOAS today) never win, which falls out of the comparison.
pub fn fork_at_epoch(&self, epoch: u64) -> Fork {
    self.forks
        .iter()
        .rfind(|f| f.epoch <= epoch)
        .copied()
        // Before the first scheduled fork, genesis governs.
        .unwrap_or(self.forks[0])
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures)* `rfind` searches from the back of a double-ended iterator, and `.copied()` turns `Option<&Fork>` into `Option<Fork>`. `unwrap_or(self.forks[0])` evaluates its argument on every call (use `unwrap_or_else` for anything expensive), and the indexing can't panic, because the private constructor refuses an empty fork list.

<a id="f-roost-src-framing-rs"></a>

### roost/src/framing.rs

*binary · 343 lines · Java twin · (encoder) ReqRespCodec*

Splits Nimbus's `light_client/updates` REST body (`u64 LE length | digest | SSZ`, repeated) into per-period chunks, trusting only the length prefix, and re-frames them as a libp2p multi-chunk response with `myotis-net`'s own encoder (`myotis_net::codec`, a re-export of `myotis-wire`'s `eth2::codec`). The digest is re-emitted as received, never derived. It uses the same protocol stack the wallets are tested against.

`rust/roost/src/framing.rs` · lines 63–85

```rust
/// Why a REST updates body could not be walked.
///
/// Every variant carries the offset it failed at: with a concatenated body, "it
/// didn't parse" is useless for telling a truncated download from a bad chunk
/// halfway in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    /// Fewer than 8 bytes remain where a length prefix should start.
    TruncatedLength { offset: usize, remaining: usize },
    /// The declared length does not fit in a `usize` (32-bit hosts) or would
    /// overflow when added to the offset.
    LengthOverflow { offset: usize, declared: u64 },
    /// Declared length exceeds [`MAX_CHUNK_BYTES`].
    ChunkTooLarge { offset: usize, declared: usize },
    /// Declared length leaves no room for the 4-byte fork digest.
    ChunkTooShort { offset: usize, declared: usize },
    /// The body ends before the declared chunk does.
    TruncatedChunk {
        offset: usize,
        need: usize,
        have: usize,
    },
}
```

`rust/roost/src/framing.rs` · lines 121–183

```rust
pub fn split_updates(body: &[u8]) -> Result<Vec<UpdateChunk>, FramingError> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;

    while offset < body.len() {
        // --- length prefix -------------------------------------------------
        let body_start = offset
            .checked_add(LENGTH_PREFIX_LEN)
            .ok_or(FramingError::LengthOverflow {
                offset,
                declared: 0,
            })?;
        let prefix = body
            .get(offset..body_start)
            .ok_or(FramingError::TruncatedLength {
                offset,
                remaining: body.len() - offset,
            })?;
        // The slice is exactly LENGTH_PREFIX_LEN long by construction.
        let declared_u64 = u64::from_le_bytes(prefix.try_into().expect("8-byte slice"));

        let declared =
            usize::try_from(declared_u64).map_err(|_| FramingError::LengthOverflow {
                offset,
                declared: declared_u64,
            })?;
        if declared > MAX_CHUNK_BYTES {
            return Err(FramingError::ChunkTooLarge { offset, declared });
        }
        // The length covers digest + update, so anything under 4 cannot even
        // carry the digest — and a 4-byte chunk would be a digest with an empty
        // update, which is equally malformed.
        if declared <= FORK_DIGEST_LEN {
            return Err(FramingError::ChunkTooShort { offset, declared });
        }

        // --- chunk body ----------------------------------------------------
        let chunk_end = body_start
            .checked_add(declared)
            .ok_or(FramingError::LengthOverflow {
                offset,
                declared: declared_u64,
            })?;
        let chunk = body
            .get(body_start..chunk_end)
            .ok_or(FramingError::TruncatedChunk {
                offset,
                need: declared,
                have: body.len() - body_start,
            })?;

        let mut fork_digest = [0u8; FORK_DIGEST_LEN];
        fork_digest.copy_from_slice(&chunk[..FORK_DIGEST_LEN]);
        chunks.push(UpdateChunk {
            fork_digest,
            ssz: chunk[FORK_DIGEST_LEN..].to_vec(),
        });

        offset = chunk_end;
    }

    Ok(chunks)
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling)* **A typed error in an `anyhow` binary.** Every variant carries the failing offset. `impl std::error::Error` lets `anyhow` callers use `?` (`split_updates(..)?`). `#[derive(PartialEq, Eq)]` lets tests `assert_eq!` exact errors. This file spells out `Result<_, FramingError>` and never imports `anyhow`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Checked conversions.** `usize::try_from(u64)` can fail on 32-bit hosts, and `checked_add` guards every offset. `ok_or(…)` builds its error value eagerly, which is fine for a small enum with no allocation; `ok_or_else` would defer it. The subtractions inside can't underflow, thanks to the loop guard and the successful `get` just before.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Lifetimes](01-primer.md#primer-lifetimes)* **Why copy.** `chunk` borrows the caller's body. The digest is copied into a 4-byte stack array and the payload into a new `Vec`, so `UpdateChunk` owns its data, needs no lifetime parameter, and can outlive the HTTP buffer on its way into the archive and the store.
- *[Protocol & domain](01-primer.md#primer-domain)* An empty body is `Ok(vec![])`, which is how Nimbus answers for a period below its window. Chunks vary by a few bytes, so a fixed stride would be wrong.

<a id="f-roost-src-serve-rs"></a>

### roost/src/serve.rs

*binary · daemon · 1,569 lines*

`roost serve`. At startup it loads the archive into the store, fills missing periods, resolves digests, starts `myotis-net`'s libp2p host with the store plugged in as the light-client responder, and joins discv5. Then, on a 12-second tick, it refreshes live objects, fills requested bootstraps and the new period, keeps `status` honest, tracks its external IP, and publishes the ENR once every gate passes.

`rust/roost/src/serve.rs` · lines 403–421

```rust
pub async fn serve(
    rest_base: &str,
    archive_path: &Path,
    key_path: Option<PathBuf>,
    port: u16,
    publish_enr: bool,
) -> Result<()> {
    let client = NimbusRest::new(rest_base, Duration::from_secs(30))?;
    let gvr = client.genesis_validators_root().await?;
    // REQUIRED, and fetched before the archive is opened: every period number
    // below — including the keys archive records are written under — depends on
    // it, and a wrong value mis-keys durable data rather than failing.
    let (params, initial_schedule) = ForkSchedule::fetch_with_params(&client, gvr).await?;

    let (mut archive, records, report) = Archive::open(archive_path, &gvr)?;
    let store = Arc::new(LcStore::new());
    for (period, rec) in &records {
        store.insert_update(*period, rec.fork_digest, &rec.ssz);
    }
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Strict startup.** The genesis root and the chain geometry are required *before* the archive is opened, because every record key depends on them. `for (period, rec) in &records` iterates by reference: `*period` copies the key, and `&rec.ssz` borrows the bytes. Best-effort steps (the initial fill, live objects, discovery) only log.

`rust/roost/src/serve.rs` · lines 487–505

```rust
let (net, peer_id, swarm_task) = start_host_with(
    status.clone(),
    HostConfig {
        listen,
        // No QUIC listener yet: the relay forwards no spare UDP port for
        // it (discv5 holds the ones there are) and the ENR carries no
        // `quic` field, so an inbound QUIC socket here would be
        // unreachable and unadvertised. Follow-up, with a forwarded port.
        listen_quic: None,
        max_established_incoming: Some(MAX_INBOUND),
        keypair: Some(keypair.clone()),
        lc_responder: Some(store.clone()),
        // A server follows its beacon node's schedule; nothing to warn about.
        cl_fork_watch: None,
        // A server reports no data usage.
        traffic: None,
    },
)
.map_err(|e| anyhow!("starting the libp2p host: {e}"))?;
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Plugging the store in.** `store.clone()` is an `Arc<LcStore>` reference-count bump, and the field type `Option<Arc<dyn LcResponder>>` coerces it into a trait object (a pointer to the data plus a vtable), like passing an object as its interface type. The spawned swarm task and this task now share the store and the status. What comes back is an actor mailbox (`net`: an `mpsc` channel with `oneshot` replies), the peer id, and the swarm task's `JoinHandle`.

*[Methods & self](01-primer.md#primer-methods) · [Protocol & domain](01-primer.md#primer-domain)* **Every field, spelled out.** A Rust struct literal must name every field, unless it ends with `..base` to copy the rest from another value. roost writes all seven, so when `myotis-net` added `listen_quic`, `cl_fork_watch` and `traffic`, this call stopped compiling until someone decided each one. That matters here: `HostConfig::default()` is the wallet's shape and opens an ephemeral QUIC listener, which a server must not do, because the relay forwards no UDP port for it and the ENR does not advertise one. `..HostConfig::default()` would have accepted that silently. Java has no equivalent check; a builder with a new optional setter compiles everywhere.

`rust/roost/src/serve.rs` · lines 564–604

```rust
let mut digests = digests;
let mut external: Option<ExternalAddress> = None;
let mut upstream_ip: Option<IpAddr> = None;
// What the published record currently advertises. None until the first
// publish of this run; a restart always re-publishes once (with a bumped
// sequence number), which is what re-asserts the record after downtime.
let mut published: Option<(IpAddr, [u8; 16])> = None;
// The last logged publication refusal, so a steady state logs once rather
// than every tick.
let mut publish_refusal: Option<&'static str> = None;
let mut swarm_task = swarm_task;
let mut ticks: u32 = 0;
let mut ticker = tokio::time::interval(REFRESH);
ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
loop {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down");
            return Ok(());
        }
        // The swarm task owns the listener and every connection. If it ends
        // we are no longer serving anything, but the process would happily
        // keep polling Nimbus forever — a silent outage no supervisor can
        // see, because `Restart=` only acts on a process that exits. So
        // exit, loudly, and let the unit restart us.
        joined = &mut swarm_task => {
            let how = match joined {
                Ok(()) => "returned".to_string(),
                Err(e) if e.is_panic() => "PANICKED".to_string(),
                Err(e) => format!("failed: {e}"),
            };
            tracing::error!(outcome = %how, "libp2p swarm task ended — no longer serving");
            return Err(anyhow!("libp2p swarm task ended ({how}) — exiting so the supervisor can restart us"));
        }
        _ = ticker.tick() => {
            // Every failure here is logged and swallowed: a REST hiccup must
            // degrade what we serve, never take the responder down. A stale
            // relay surfaces to wallets as "not ready", which is the
            // detectable failure the design accepts.
            ticks = ticks.wrapping_add(1);
            let head_slot_hint = status.get().head_slot;
```

- *[async/await & tokio](01-primer.md#primer-async)* **`select!` in a loop.** It waits for whichever future finishes first and runs only that arm; the others are dropped. Arm bodies are ordinary code in the enclosing function, not closures, so `return` leaves `serve`. `interval` fires its first tick immediately, and `MissedTickBehavior::Skip` prevents a burst of catch-up ticks after a slow one.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* **A `JoinHandle` polled by `&mut`.** Passing `swarm_task` by value would move it into the first `select!`, and the next iteration wouldn't compile (“use of moved value”). Hence `let mut swarm_task = swarm_task;` and `&mut swarm_task`.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **The real containment story.** Under `panic = "unwind"`, a panic in the swarm task arrives here as a *value*: `Err(e) if e.is_panic()`. The daemon logs it and returns `Err`, so the process exits non-zero and systemd (`Restart=on-failure`) restarts it. Without this arm, the process would keep polling Nimbus with no listener, an outage no supervisor could see. All connections still drop: requests are answered on that one task.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `archive`, `digests`, `external`, `published` and `ticks` are plain locals of this future. Nothing else can reach them, so they need no locks, like state confined to a single-threaded executor. `publish_refusal: Option<&'static str>` stores literals, so they can be compared to log a refusal only when it changes.

> [!WARNING]
> **Two shutdown caveats**
>
> - `tokio::signal::ctrl_c()` is created afresh on each iteration, and per tokio's documentation it completes only for a Ctrl-C received *after* it was first polled. While a tick body is running, that future has already been dropped, so a Ctrl-C pressed during a tick can be missed; press it again. Creating it once and polling it by `&mut`, as with `swarm_task`, would fix that.
> - Only SIGINT is handled. `systemctl stop` sends SIGTERM, whose default action ends the process without running this path. The append-only archive with torn-tail repair tolerates that.

`rust/roost/src/serve.rs` · lines 1244–1281

```rust
async fn fill_bootstrap_misses(
    client: &NimbusRest,
    store: &LcStore,
    digests: &Digests,
    head_slot: u64,
) -> Result<usize> {
    let mut filled = 0;
    for root in store.take_bootstrap_misses(MISS_FETCHES_PER_TICK) {
        match client.bootstrap_classified(&root).await {
            Ok(bs) => {
                let digest = bootstrap_digest(client, digests, &root, head_slot).await;
                store.insert_bootstrap(root, digest, &bs.bytes);
                filled += 1;
                tracing::info!(root = %hex::encode(&root[..8]), bytes = bs.bytes.len(),
                    "filled a requested bootstrap");
            }
            // Definitive: the upstream answered and does not have it (typically
            // below its light-client window). The attempted marker set by the
            // drain is correct — asking again would cost a fetch per retry of a
            // wallet that will keep asking forever.
            Err(FetchError::Unavailable(code)) => {
                tracing::info!(root = %hex::encode(&root[..8]), code,
                    "upstream does not have this bootstrap — not retrying");
            }
            // Transient: a timeout, a connection failure, a 5xx. The drain
            // already marked it attempted, so leaving it there would make ONE
            // Nimbus hiccup permanently poison a wallet's pinned checkpoint —
            // every later request refused with ResourceUnavailable and no
            // re-fetch. Put it back at the front of the queue instead.
            Err(FetchError::Transient(e)) => {
                tracing::warn!(root = %hex::encode(&root[..8]), error = %e,
                    "transient failure fetching a bootstrap — requeued");
                store.requeue_bootstrap_miss(root);
            }
        }
    }
    Ok(filled)
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* A wallet's first request is always for its *own* pinned checkpoint, which no pre-population can guess. So a miss is queued, and here, at most 4 per tick, it is fetched. `match` on the typed `FetchError`: `Unavailable` keeps the root marked as attempted (no refetch storms), while `Transient` puts it back at the front of the queue, so one hiccup can't block that checkpoint for good. `store: &LcStore` is borrowed straight through the `Arc` via deref coercion.

<a id="f-roost-src-enr-rs"></a>

### roost/src/enr.rs

*binary · 162 lines*

A persisted, strictly increasing ENR sequence number. The DHT keeps only the highest-sequence record per node, so a counter that reset on restart would make every later record, including an IP change, silently ignored. `load` starts at 1 if the file is missing and fails hard on a corrupt file.

`rust/roost/src/enr.rs` · lines 36–47

```rust
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
```

`rust/roost/src/enr.rs` · lines 56–109

```rust
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
    if let Some(parent) = self.path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // Write, FSYNC, then rename. `fs::write` alone returns once the data is
    // in the page cache: rename makes the NAME change atomic and says
    // nothing about the contents being on disk, so a power loss can leave a
    // renamed file of length zero. That is normally a shrug — but `load`
    // deliberately refuses to recover from a corrupt file, so the residue
    // would be a startup failure until someone wrote a number back by hand.
    // The write side should make the state the read side hard-fails on
    // unreachable, not merely unlikely.
    //
    // The temp name carries the pid so two instances sharing a data
    // directory cannot race on the same path.
    let tmp = self
        .path
        .with_extension(format!("seq.tmp.{}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(next.to_string().as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &self.path)
        .with_context(|| format!("renaming into {}", self.path.display()))?;
    // fsync the DIRECTORY too: syncing the file makes its contents durable,
    // but the rename is a directory operation and can still be lost on power
    // loss. The invariant here is persistence-BEFORE-use — a sequence number
    // that was returned but not durable lets a later record reuse a value the
    // DHT has already seen, and the DHT then ignores every record until the
    // count climbs back past it. The node looks healthy and is undiscoverable.
    if let Some(dir) = self.path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    self.current = next;
    Ok(next)
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `Err(e) if e.kind() == NotFound => 1` is a guarded arm on an I/O error kind. `return Err(e).with_context(…)` adds a message to a plain `io::Error`. `.context(…)` on an `Option` (from `checked_add`) turns `None` into an error.
- *[Ownership & moves](01-primer.md#primer-ownership)* **A scoped block** limits both the `use std::io::Write;` and the `File`: the file is closed at `}`, before the rename. `with_context(|| …)` builds its message only on failure.
- *[Protocol & domain](01-primer.md#primer-domain)* **Persist before use.** Write the temp file, fsync it, rename it, then fsync the directory. A number that was handed out but not safely stored could be issued again after a crash, and the DHT would ignore every record until the count climbed past it. (The module doc still says publishing is “not wired up here”, which is true of this file only: `serve.rs` publishes now.)

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-roost-q1"></a>

**Q1** · Multiple choice

roost builds with `panic = "unwind"`. If `LcStore::updates_range` panicked while answering one wallet, what would happen?

- **A.** Only that wallet's connection would close
- **B.** The swarm task, which answers all requests inline, would end. `serve` sees `JoinError::is_panic()`, logs it, and exits non-zero, and systemd restarts roost. Every connection drops
- **C.** The panic is silently ignored
- **D.** The process aborts without any log line

[Answer →](answers.md#a-roost-q1)

<a id="q-roost-q2"></a>

**Q2** · Multiple choice

Why is `LcStore` guarded by `std::sync::RwLock` rather than `tokio::sync::RwLock`?

- **A.** tokio has no RwLock
- **B.** Its reader, `respond_inbound`, is synchronous code on the swarm task. It can't `.await` an async lock, and `block_on` inside a runtime worker would panic. The std lock is held briefly, and never across an await
- **C.** std locks are faster in all cases
- **D.** tokio locks can't be shared through `Arc`

[Answer →](answers.md#a-roost-q2)

<a id="q-roost-q3"></a>

**Q3** · Multiple choice

`record_bootstrap_miss` checks under a read lock inside `{ }`, then takes the write lock and checks again. Why both?

- **A.** Style
- **B.** The common “nothing to do” case needs only a shared lock. The block drops the read guard first, because `std`'s `RwLock` can't upgrade, and the state may change between the two locks, so it must be re-checked
- **C.** The first check is debug-only
- **D.** The write lock is taken on another thread

[Answer →](answers.md#a-roost-q3)

<a id="q-roost-q4"></a>

**Q4** · Multiple choice

How can `Archive::append(&mut self, …)` be safe in a concurrent daemon without a `Mutex`?

- **A.** It isn't safe
- **B.** Only the main task owns the `Archive`, and `&mut` is an exclusive borrow checked at compile time. The swarm task never has a reference to it, so a second in-process writer can't exist
- **C.** File writes are atomic anyway
- **D.** tokio serialises all file I/O

[Answer →](answers.md#a-roost-q4)

<a id="q-roost-q5"></a>

**Q5** · Multiple choice

Why does `get_ssz_classified` treat HTTP 429 as `FetchError::Transient` even though it's a 4xx?

- **A.** All 4xx are transient
- **B.** A bootstrap root is marked as attempted before the fetch, and only `Transient` failures are requeued. A 429 classified as “unavailable” would leave a wallet's pinned checkpoint permanently unserved after one rate-limit answer
- **C.** 429 means the server crashed
- **D.** reqwest requires it

[Answer →](answers.md#a-roost-q5)

<a id="q-roost-q6"></a>

**Q6** · Multiple choice

`ChainParams`'s fields are private and `from_spec` is the only constructor. What does that buy?

- **A.** Faster access
- **B.** A value that refuses zero, missing or overflowing geometry is the only kind that can exist, so `slot / slots_per_period` can't divide by zero and archive keys can't be silently wrong. With `pub` fields a zero compiled
- **C.** Serialization support
- **D.** It makes the type `Copy`

[Answer →](answers.md#a-roost-q6)

<a id="q-roost-q7"></a>

**Q7** · Multiple choice

In `serve`'s loop, why is the swarm task's handle written as `joined = &mut swarm_task` inside `select!`?

- **A.** `JoinHandle` can only be polled by reference
- **B.** Passing it by value would move it into the first `select!`, and the next loop iteration wouldn't compile (use of moved value). Polling `&mut` keeps the same handle across iterations
- **C.** It makes the task run faster
- **D.** `&mut` cancels the task

[Answer →](answers.md#a-roost-q7)

<a id="q-roost-q8"></a>

**Q8** · Written answer

A fresh wallet asks roost for a `light_client_bootstrap` at its pinned checkpoint root, which roost has never seen. Describe what happens on the swarm task and on the main task until the wallet is served, including what happens if Nimbus times out, and if Nimbus answers 404.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-roost-q8)

<a id="q-roost-q9"></a>

**Q9** · Multiple choice

Why does `EnrSeq::bump` persist the new number (fsync file, rename, fsync directory) *before* returning it?

- **A.** For logging
- **B.** If roost crashed after publishing a record but before persisting, a restart would reuse a sequence number the network already saw, and the DHT ignores records that don't out-rank the one it has
- **C.** Because rename is slow
- **D.** To save memory

[Answer →](answers.md#a-roost-q9)

<a id="q-roost-q10"></a>

**Q10** · Multiple choice

Why does `UpdateChunk` own `ssz: Vec<u8>` instead of borrowing a `&[u8]` from the REST body?

- **A.** Borrowing is slower
- **B.** The chunks outlive the HTTP response buffer on their way to the archive and the store. A borrowing struct would need a lifetime parameter tied to `body`, and couldn't outlive it
- **C.** `&[u8]` can't be stored in a struct
- **D.** To enable `Clone`

[Answer →](answers.md#a-roost-q10)

<a id="q-roost-q11"></a>

**Q11** · Multiple choice

In `clear_bootstraps`, why iterate over `inner.bootstrap_order.clone()`?

- **A.** To sort it
- **B.** Both field accesses go through the same write guard (`DerefMut`), so iterating one field while mutating another looks like a shared and a mutable borrow of `inner` at once. Cloning (at most 64 roots) sidesteps that; `let i = &mut *inner;` would allow disjoint field borrows
- **C.** The clone is required by `VecDeque`
- **D.** To avoid holding the lock

[Answer →](answers.md#a-roost-q11)

<a id="q-roost-q12"></a>

**Q12** · Multiple choice

`serve` builds its `HostConfig` by naming all seven fields, including `listen_quic: None`, instead of writing `..HostConfig::default()` for the ones it does not care about. What does that buy?

- **A.** Nothing; the two forms always produce the same value
- **B.** When `myotis-net` adds a field, this literal stops compiling until roost decides the value. With `..HostConfig::default()` roost would silently inherit the wallet's defaults, such as an ephemeral QUIC listener a server must not open
- **C.** It makes the struct `Copy`
- **D.** `..default()` is not allowed for structs with `Option` fields

[Answer →](answers.md#a-roost-q12)

<a id="q-roost-q13"></a>

**Q13** · Written answer

`participation_of` now chooses between `LcFork::Gloas` and `LcFork::PreGloas` by the length of the SSZ bytes. Explain why roost may decide this way when a wallet does not, what `.ok().map(…)` does with the result, and what went wrong for Gloas periods before the change.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-roost-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
