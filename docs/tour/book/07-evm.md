# myotis-evm: an EVM over verified state

*Stop 7 · crate `myotis-evm`* · 13 files · 10,227 lines · about 3 hours

The Rust engine's EVM: `eth_call`, `eth_estimateGas`, `eth_createAccessList`, `debug_traceCall` and ENS resolution, executed by revm. Every piece of state revm reads, `BLOCKHASH` included, comes through one trait whose implementations may return only *proven* data. The crate still does no I/O. It is where you meet **shared ownership** (`Arc<dyn Trait>`) and **interior mutability** in earnest, in both of its forms: a `Mutex` where the type must be shareable across threads, a `RefCell` where it never leaves one.

## Rust you will practise

- **Borrowed views, copied handles** — `Option<&'a T>` fields, small `Copy` structs passed by value, `let … else` that copies a value out of `&self`.
- **Interior mutability, two ways** — `Mutex` guards that end at `;` or `}`, `RefCell` for one-thread recorders, `AtomicU64` counters behind `&self`.
- **Closures and ownership** — an `FnMut` callback that borrows, a `Copy` closure used twice, boxed `Fn` handlers that must clone what they captured.

## The shape of a call

A host asks `myotis-net`'s `ElReader` ([stop 14](14-el-reader.md)) for an answer. The reader builds a `BlockContext` from the verified head and an `EvmExecutor` over a fresh network-backed oracle plus long-lived shared caches, and runs it on a blocking thread. Inside this crate, `spec_for` picks the fork rules. A per-call `OracleDatabase` answers each revm read from four layers in order: **caller overrides → per-call view cache → cross-call proof cache → verified oracle fetch**. A “prefetch convergence loop” keeps the number of slow, one-at-a-time network round-trips small.

The executor now has two families of entry points. The *view-call* family (`call_view`, `call_view_from`, `call_view_overridden`, `create_view`, `estimate_gas`) takes a target, calldata and value. The *transaction-object* family (`call_tx`, `estimate_tx`, `create_access_list`, `trace_call`) takes a whole `TxRequest`: gas, fees, nonce, access list, EIP-7702 authorizations. Every field the request names is applied, or the request is refused. `TxRequest` itself, the tracers and `eth_simulateV1` live in the files of [stop 8](08-evm-sim.md). This stop covers the foundation they all stand on.

> [!NOTE]
> **What changed since September**
>
> The crate grew from 12 files and 4,873 lines to 26 files and 15,187. Half of that is stop 8's. In this stop's files: the error set went from 8 variants to 25, each sorted as a *refusal* or an *infeasible* answer for the JSON-RPC layer. The prefetch loop's cap went from 4 to 12, the oracle now bounds discovery in time, and waves follow the code of called contracts (issue #532). `BLOCKHASH`, which always failed before, is served from verified data (#664). The fork table gained Chiado, Osaka and Sepolia's Amsterdam rung. ENS gained Genome's `.gno` names on Gnosis, ownership reads, and ENSv2 awareness (#671).

<a id="f-myotis-evm-src-lib-rs"></a>

### myotis-evm/src/lib.rs

*crate root · 508 lines · Java twin · io.myotis.evm module*

The crate root: the module tree, the re-exports, and about 430 lines of unit tests for `OracleDatabase`. The crate doc states the architecture: revm behind a synchronous `SnapStateOracle`, with the async bridge living in the I/O crate that implements it. The old doc's stale “following slices” list is gone; the current one lists what exists (the executor with its prefetch loop, overrides, `tx`, the fork table for four chains, ENS).

`rust/myotis-evm/src/lib.rs` · lines 53–77

```rust
// Re-exported so downstream crates implementing [`SnapStateOracle`] / building a
// [`BlockContext`] can name revm's `U256` without depending on revm directly.
pub use revm::primitives::U256;

pub use block::BlockContext;
pub use cache::{
    BytecodeCache, InMemoryBytecodeCache, InMemoryStateProofCache, Lru, NoopBytecodeCache,
    NoopStateProofCache, StateProofCache,
};
pub use database::{BlockHashes, OracleDatabase, HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
pub use ens::{
    ccip_callback, decode_abi_answer, decode_address_answer, decode_bytes_answer,
    decode_name_answer, decode_pubkey_answer, decode_text_answer, resolve_abi, resolve_address, resolve_contenthash, resolve_dns_record,
    resolve_interface_implementer, resolve_multicoin, resolve_pubkey, resolve_text,
    reverse_forward_answer, reverse_resolve, verify_reverse_claim, EnsError, EthCaller, ExecutorCaller,
    OffchainLookup, resolve_ownership, EnsOwnership,
};
pub use ens::refusal as ens_refusal;
pub use error::EvmError;
pub use executor::{CallCost, CreatedAccessList, EvmExecutor};
pub use oracle::{OracleAccount, OracleError, SnapStateOracle, WireCost};
pub use tx::TxRequest;

#[cfg(any(test, feature = "fixture"))]
pub use oracle::FixtureSnapStateOracle;
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `pub use` re-exports items at a shorter path (a facade). Re-exporting revm's `U256` lets downstream crates name it without depending on revm directly. `pub use ens::refusal as ens_refusal;` also *renames*: outside the crate the function is `myotis_evm::ens_refusal`, which reads better at a call site than a bare `refusal`. `overrides`, `simulate` and `trace` are public modules but not flattened, so callers write `myotis_evm::overrides::StateOverrides`.
- *[Tests](01-primer.md#primer-testing) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `#[cfg(any(test, feature = "fixture"))]` (lines 76–77, and on `pub mod fixture` at lines 44–45): `cfg(test)` is set only while compiling *this* crate's tests, so other crates must opt in through the `fixture` feature, much like Gradle's `testFixtures`.

`rust/myotis-evm/src/lib.rs` · lines 433–456

```rust
    let oracle = Arc::new(OneShot {
        calls: AtomicUsize::new(0),
        acc: acct(500, 1, EMPTY_CODE_HASH),
    });
    let proofs: Arc<dyn StateProofCache> = Arc::new(InMemoryStateProofCache::new(16));
    // First call populates the shared proof cache, then is discarded.
    {
        let d1 = db(
            Arc::clone(&oracle) as Arc<dyn SnapStateOracle>,
            ROOT_A,
            Arc::clone(&proofs),
            Arc::new(NoopBytecodeCache),
        );
        assert_eq!(d1.basic_ref(Address::from(ADDR)).unwrap().unwrap().nonce, 1);
    }
    // Fresh call (new view cache); the oracle would now error, so success
    // proves the cross-call cache served it.
    let d2 = db(oracle, ROOT_A, proofs, Arc::new(NoopBytecodeCache));
    let info = d2
        .basic_ref(Address::from(ADDR))
        .unwrap()
        .expect("cross-call hit");
    assert_eq!(info.balance, U256::from(500));
}
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* A test that reads like a memory-model lesson. `Arc::clone(&oracle) as Arc<dyn SnapStateOracle>` makes a second, interface-typed pointer to the same object while the test keeps the concrete one. `d1` and its per-call cache die at the closing `}` on line 447, but the shared proof cache survives because `proofs` still points at it. On line 450, `oracle` and `proofs` are *moved* rather than cloned, because neither is needed afterwards. The test oracle counts calls with an `AtomicUsize`: its methods take `&self` and the trait requires `Sync`, so a `Cell` would not compile.

<a id="f-myotis-evm-src-error-rs"></a>

### myotis-evm/src/error.rs

*library · 319 lines · Java twin · EvmExecutionError*

`EvmError` is the closed set of ways an EVM request can end other than with success bytes: oracle failure, revert (with raw data), out of gas, other halt, fork too old, unsupported chain, rejected envelope, a loop that did not converge, and seventeen newer variants for transaction objects, estimates, access lists and simulations. Most of the new ones carry geth's exact wording in `Display`, because wallets match on those strings. Two classifier methods tell a host how to serve each one.

`rust/myotis-evm/src/error.rs` · lines 132–174

```rust
impl EvmError {
    /// True when this call can never be answered on this build: hosts must
    /// serve a PERMANENT error (JSON-RPC -32602), never the retryable
    /// "unavailable" a client would spin on (CLAUDE.md apply-or-refuse).
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            EvmError::MissingSlotNumber { .. }
                | EvmError::UnexpectedSlotNumber { .. }
                | EvmError::InvalidRequest { .. }
                | EvmError::CallBudgetExceeded { .. }
                | EvmError::SimulationNotServed { .. }
                | EvmError::Oracle(OracleError::BlockHashUnsupported { .. })
        )
    }

    /// True when the request was understood and the answer is that the
    /// transaction cannot succeed within the caller's own limits (gas, funds,
    /// fee cap). Hosts serve it as geth does — JSON-RPC -32000 carrying this
    /// error's message — and never as a number or return data: a wallet that
    /// broadcast one would lose the fee.
    pub fn is_infeasible(&self) -> bool {
        matches!(
            self,
            EvmError::GasAllowanceExceeded { .. }
                | EvmError::InsufficientFundsForTransfer
                | EvmError::InsufficientFunds { .. }
                | EvmError::FeeCapTooLow { .. }
                | EvmError::IntrinsicGasTooLow { .. }
                | EvmError::FloorDataGasTooLow { .. }
                | EvmError::CallOutOfGas
                | EvmError::FailedWithGas { .. }
                | EvmError::RequiredBalanceOverflow { .. }
                | EvmError::CallFailed { .. }
        )
    }
}

impl From<OracleError> for EvmError {
    fn from(e: OracleError) -> EvmError {
        EvmError::Oracle(e)
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `matches!(value, pattern)` is a macro that expands to a `match` returning `true` or `false`. The pattern uses `|` to list alternatives and `{ .. }` to ignore fields. It can reach into a nested enum: line 144 matches only the `BlockHashUnsupported` arm of the wrapped `OracleError`.
- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Three classes of failure.** A *refusal* can never be answered on this build (a request no transaction could be, an Amsterdam block the fork table does not know), so hosts serve the permanent JSON-RPC code −32602. An *infeasible* request was understood, and the answer is that it fails within the caller's own limits (gas, funds, fee cap); hosts serve −32000 with geth's message. Everything else (a revert, state that could not be fetched) goes to the host's ordinary mapping. This is the `CLAUDE.md` rule “apply or refuse” turned into types.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `impl From<OracleError> for EvmError` (lines 170–174) is what lets `?` turn an oracle error into an `EvmError` automatically. The [primer](01-primer.md#primer-error-handling) walks through this mechanism.

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* Two variants wrap another `EvmError`: `FailedWithGas { gas, error: Box<EvmError> }` and `CallFailed { supplied_gas, error: Box<EvmError> }` (lines 95 and 110). An enum's size is the size of its largest variant, so an enum that contained itself directly would need infinite size. The `Box` puts the inner error on the heap and leaves a pointer in the variant. `kind()` (lines 176–209) returns a `&'static str`, a string literal that lives for the whole program, so the caller gets a name it can log without owning anything. Its arm `EvmError::FailedWithGas { error, .. } | EvmError::CallFailed { error, .. } => error.kind()` binds the same name in both alternatives, which Rust allows only when the types agree. `kind()` exists so an info-level log line names the error without its values (an address, a balance; #532 review).

> [!WARNING]
> **Stale or inaccurate comments**
>
> The `ForkTooOld` doc (line 25) and its message (line 222, “pre-London blocks are not supported”) describe only mainnet. On Sepolia, Gnosis and Chiado the floor is Shanghai (see [fork.rs](#f-myotis-evm-src-fork-rs)). The old `UnsupportedChain` text that said “mainnet-only” has been fixed.

<a id="f-myotis-evm-src-oracle-rs"></a>

### myotis-evm/src/oracle.rs

*library · 380 lines · Java twin · io.myotis.evm.world.SnapStateOracle*

The trust boundary of the whole engine: the `SnapStateOracle` trait (the EVM's only source of state), `OracleAccount`, the closed `OracleError`, `WireCost`, and the in-memory test oracle. Accounts and storage must be proven against `state_root`, bytecode must hash to its code hash, and a block hash must be proven by a header chain; otherwise the oracle returns an error. It never returns unverified data.

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

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Required and provided methods.** Only the three `fetch_*` methods without a body are required. `check_request`, `wire_cost`, `keep_discovering`, and below `fetch_block_hash` and `prefetch_batch`, have default bodies, like Java interface `default` methods. A test fixture implements three methods and inherits sensible behaviour for the rest: never cancelled, nothing measured, discovery unbounded, no header source, no batch warm-up.
- *[async/await & tokio](01-primer.md#primer-async) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Why synchronous?** revm's database interface is synchronous, and an async trait would drag a runtime into this crate. So implementations may *block*, and the caller must run the EVM on a worker thread. The production bridge is `PoolOracle` in `myotis-net/src/el/evm.rs` ([stop 13](13-el-services.md)), whose waits use `Handle::block_on`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `SnapStateOracle: Send + Sync` (line 186) makes `Arc<dyn SnapStateOracle>` itself `Send`, so an executor holding one can be moved into a blocking task.
- *[Protocol & domain](01-primer.md#primer-domain)* **The oracle owns the clock.** `keep_discovering(pass)` lets the oracle stop the prefetch loop's discovery passes after a time budget. This crate holds no clock (it is sans-I/O), so the decision is delegated. `PoolOracle`'s version records an `Instant` at pass 0 and compares against its budget. The doc is explicit that the answer never depends on it: past the bound the loop simply fetches what is left one read at a time.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* The return type `Result<Option<OracleAccount>, OracleError>` encodes three outcomes: proven present (`Ok(Some)`), proven absent (`Ok(None)`), and unprovable (`Err`).

*[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* Below the excerpt, `fetch_block_hash(anchor_number, anchor_hash, number)` (lines 242–249) asks for a block hash proven by a header chain that links down from the call block's parent. Its default returns `BlockHashUnsupported`, never zero. `prefetch_batch` (lines 257–265) is the best-effort parallel warm-up: it writes verified results into the two cache “sinks” and is silent on failure, because the per-item path refetches whatever is missing.

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `OracleError` (lines 63–96) has six variants. `InvalidProof` is flagged as security-critical: a peer served data inconsistent with the anchored root. `BlockHashUnsupported` (no source can ever serve it, a refusal) and `BlockHashUnavailable` (no peer served the header chain this time, retryable) are kept apart so a host can tell “never” from “not now”.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Lifetimes](01-primer.md#primer-lifetimes)* revm requires its database error type to implement `DBErrorMarker` (line 153), which in turn needs `Error + Send + Sync + 'static`. That is why `OracleError` implements `std::error::Error`, and why it owns its `String`s instead of borrowing them.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `kind()` (lines 137–147) uses a **match guard**: `Cancelled { reason } if reason == "request deadline exceeded" => …` takes that arm only when the condition holds, and otherwise falls to the next `Cancelled { .. }` arm. Matching on `&self` binds `reason` as a `&String`, which compares with a `&str` literal directly.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `hex()` (lines 155–164) writes into one preallocated `String` with `write!`, avoiding a temporary `String` per byte. `let _ = write!(…)` discards a `Result` that cannot be an error for a `String` target.

*[Ownership & moves](01-primer.md#primer-ownership)* The fixture's builders show two styles. `with_account(mut self, …) -> Self` and `with_block_hash(mut self, …) -> Self` take the builder by value and hand it back, for chaining. `with_bytecode(&mut self, …) -> [u8; 32]` borrows instead, because it returns the computed code hash.

> [!WARNING]
> **Stale or inaccurate comments**
>
> The `OracleError` doc (lines 60–62) says the execution arms (Reverted, OutOfGas, …) are “added in a later Milestone-C slice”. They exist, in `EvmError`.

<a id="f-myotis-evm-src-cache-rs"></a>

### myotis-evm/src/cache.rs

*library · 251 lines · Java twin · StateProofCache.inMemory*

Two pluggable cache tiers, unchanged since September. `StateProofCache` is keyed by state root, which makes it safe to share across calls, since state at a fixed root never changes. Its `get_account` returns `Option<Option<OracleAccount>>`: the outer `None` is a cache miss, while `Some(None)` is a cached, *proven absence*, two kinds of “nothing” kept apart by the type system. `BytecodeCache` is keyed by code hash and never evicts. The file also has `Lru`, a small bounded map the EL reader reuses for its block-hash → number map.

`rust/myotis-evm/src/cache.rs` · lines 95–101

```rust
impl StateProofCache for InMemoryStateProofCache {
    fn get_account(&self, root: &[u8; 32], addr: &[u8; 20]) -> Option<Option<OracleAccount>> {
        self.accounts.lock().unwrap().get(&(*root, *addr)).cloned()
    }
    fn put_account(&self, root: &[u8; 32], addr: &[u8; 20], account: Option<OracleAccount>) {
        self.accounts.lock().unwrap().put((*root, *addr), account);
    }
```

- *[Interior mutability](01-primer.md#primer-interior-mutability)* The struct's fields are `accounts: Mutex<Lru<…>>` and `storage: Mutex<Lru<…>>`. The `Mutex` owns the map, which is reachable only through a guard: a compiler-enforced `synchronized`. `.unwrap()` on `lock()` panics only if another thread panicked while holding the lock (a *poisoned* lock).
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* Line 97, `self.accounts.lock().unwrap().get(&(*root, *addr)).cloned()`: the guard is a temporary that dies at the `;`, and a reference into the map may not outlive it. So the value is `.cloned()` out. Returning `Option<&OracleAccount>` would not compile. `*root` and `*addr` copy the arrays into the tuple key.

`rust/myotis-evm/src/cache.rs` · lines 180–222

```rust
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        match self.map.get_mut(key) {
            Some(entry) => {
                entry.1 = tick;
                Some(&entry.0)
            }
            None => None,
        }
    }

    pub fn put(&mut self, key: K, value: V) {
        if self.cap == 0 {
            return;
        }
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            self.evict_lru();
        }
        self.map.insert(key, (value, tick));
    }

    fn evict_lru(&mut self) {
        // Lowest tick == least recently touched. Ticks are monotonic within the
        // map's lifetime; a `wrapping_add` overflow would need 2^64 operations,
        // far beyond any process lifetime, so ordering is effectively total.
        //
        // O(len) scan per eviction: sub-millisecond even at the 65 536-entry
        // cap and dwarfed by the network fetch that precedes every insert —
        // but if EL-C-3-2's batch fan-out makes inserts burst (64/chunk), move
        // to an ordered/amortized structure before raising capacity again.
        if let Some(victim) = self
            .map
            .iter()
            .min_by_key(|(_, (_, t))| *t)
            .map(|(k, _)| k.clone())
        {
            self.map.remove(&victim);
        }
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* The surrounding `impl<K: Hash + Eq + Clone, V> Lru<K, V>` (line 171) means the methods exist only for key types satisfying those bounds. `Clone` is needed for the eviction trick below.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `get(&mut self)` takes *exclusive* access because reading updates recency. That is why the caches use `Mutex`, not `RwLock`: there are no pure reads.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* In `evict_lru`, `self.map.iter()` is a shared borrow of the map. `.map(|(k, _)| k.clone())` copies the victim key *out*, which ends the iterator's borrow, so `self.map.remove(&victim)` may borrow mutably. Removing while iterating, the Java `ConcurrentModificationException`, is prevented at compile time.

<a id="f-myotis-evm-src-block-rs"></a>

### myotis-evm/src/block.rs

*library · 80 lines · Java twin · BlockContext*

One call's verified block inputs: the state root (which world to read), the number and timestamp (which fork applies), the opcode inputs (base fee, coinbase, prevrandao, chain id, gas limit) and two optional fields added since September. `parent_hash: Option<[u8; 32]>` is what `BLOCKHASH(N-1)` returns and where a header walk starts; `None` only for a fixture recorded before the field existed. `slot_number: Option<u64>` is the EIP-7843 slot that Amsterdam headers carry for the new `SLOTNUM` opcode. Every field must come from the verified header, never from the local clock, because a local timestamp could select different fork rules than the network.

`rust/myotis-evm/src/block.rs` · lines 67–79

```rust
pub fn block_env(&self) -> BlockEnv {
    BlockEnv {
        number: U256::from(self.block_number),
        timestamp: U256::from(self.timestamp),
        gas_limit: self.gas_limit,
        basefee: self.base_fee_per_gas,
        beneficiary: Address::from(self.coinbase),
        difficulty: U256::ZERO,
        prevrandao: Some(B256::from(self.prev_randao)),
        slot_num: self.slot_number.unwrap_or(0),
        ..BlockEnv::default()
    }
}
```

*[Ownership & moves](01-primer.md#primer-ownership)* `..BlockEnv::default()` fills the remaining fields, like Kotlin's `copy()`. `self.prev_randao` is a `Copy` array, so reading it through `&self` copies it. `self.slot_number.unwrap_or(0)` reads an `Option<u64>`, which is also `Copy`, so nothing is moved out of `self`. The doc above the method explains why the `0` is never observable: before Amsterdam `SLOTNUM` is an invalid opcode, and from Amsterdam on the executor has already refused a context without a slot. `BlockContext` derives `Clone` but not `Copy`, so callers pass it by reference.

<a id="f-myotis-evm-src-database-rs"></a>

### myotis-evm/src/database.rs

*library · 511 lines · Java twin · SyncStateView + AccessTracker*

`OracleDatabase` is how revm reads state: a `DatabaseRef` implementation over the oracle and the caches, pinned to one `state_root` and built per call. A read tries the caller's overrides, then the per-call view cache, then the cross-call proof cache, then a verified fetch (stored into both caches). For the prefetch loop it has a *sentinel mode*, which returns a counted, uncached zero placeholder instead of fetching, and it records every account, slot and code hash a run touched in an `AccessSet`. New since September: the overrides live here, and `BLOCKHASH` is answered from verified data.

`rust/myotis-evm/src/database.rs` · lines 162–179

```rust
/// A `revm` state source backed by a verified oracle + the caches, pinned to one
/// block's `state_root`.
pub struct OracleDatabase {
    oracle: Arc<dyn SnapStateOracle>,
    state_root: [u8; 32],
    proof_cache: Arc<dyn StateProofCache>,
    bytecode_cache: Arc<dyn BytecodeCache>,
    view: Mutex<ViewCache>,
    track: Mutex<Track>,
    /// Caller-supplied state for THIS call only (see [`crate::overrides`]).
    /// Consulted ahead of every tier, and never written back to any of them —
    /// an overridden value is a hypothesis, not a verified fact, and must not
    /// outlive the call or leak into a cache another call reads.
    overrides: StateOverrides,
    /// Where `BLOCKHASH` reads from; `None` refuses it
    /// ([`OracleError::BlockHashUnsupported`]).
    block_hashes: Option<BlockHashes>,
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* Three `Arc<dyn …>` fields share the oracle and caches with the executor and with other calls. `view` and `track` are this call's own mutable state, wrapped in `Mutex`. A `RefCell` would make the type non-`Sync`, and revm's `&self` database is shared by reference.
- *[Ownership & moves](01-primer.md#primer-ownership)* `overrides: StateOverrides` is *owned* by the database: the caller hands its overrides over at construction and they die with the database at the end of the call. The doc comment states the trust rule: an override is consulted ahead of every tier and never written back into any of them.

`rust/myotis-evm/src/database.rs` · lines 239–286

```rust
/// Snapshot AND clear the per-iteration access set (misses stay cumulative).
pub fn take_access_set(&self) -> AccessSet {
    std::mem::take(&mut self.track.lock().unwrap().set)
}

/// Resolve an account through the three tiers. Returns the cached/ fetched
/// account, or `None` when proven absent.
fn account(&self, addr: [u8; 20]) -> Result<Option<OracleAccount>, OracleError> {
    self.track.lock().unwrap().set.accounts.insert(addr);
    // Tier 1 — this call.
    if let Some(cached) = self.view.lock().unwrap().accounts.get(&addr) {
        return Ok(cached.clone());
    }
    // Tier 2 — a verified fact from an earlier call at this root. `Some(None)`
    // is a cached ABSENCE (exclusion proof), still a hit — don't re-fetch.
    if let Some(maybe_acc) = self.proof_cache.get_account(&self.state_root, &addr) {
        self.view
            .lock()
            .unwrap()
            .accounts
            .insert(addr, maybe_acc.clone());
        return Ok(maybe_acc);
    }
    // Sentinel: a would-be network fetch instead hands out a zero-shaped
    // placeholder (revm sees a nonexistent account), UNCACHED so a later
    // real pass re-fetches, and counts the miss.
    {
        let mut track = self.track.lock().unwrap();
        if track.sentinel {
            track.misses += 1;
            return Ok(None);
        }
    }
    // Tier 3 — a fresh verified fetch. The lock is NOT held across it: the
    // oracle may block on the network, and a call runs single-threaded so
    // there is no concurrent view-cache writer to race. Both a present account
    // and a proven absence (`None`) are promoted to the cross-call cache.
    let fetched = self.oracle.fetch_account(&self.state_root, addr)?;
    self.proof_cache
        .put_account(&self.state_root, &addr, fetched.clone());
    self.view
        .lock()
        .unwrap()
        .accounts
        .insert(addr, fetched.clone());
    Ok(fetched)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Interior mutability](01-primer.md#primer-interior-mutability)* `std::mem::take(&mut self.track.lock().unwrap().set)` (line 241) moves the access set out through the guard and leaves an empty one. In Java that is a `synchronized` block doing `var s = set; set = new AccessSet(); return s;`.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Where each guard dies.** Line 248: at the `;`. Line 250: in an `if let`, the temporary guard lives through the body (edition 2021 rules, which this crate uses), so `cached` may point into the map, and it is cloned before returning. Lines 266–272: an explicit block `{ … }` releases the lock *before* the potentially slow network fetch on line 277.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* A Rust `Mutex` is **not reentrant**. Locking it again on the same thread while holding it deadlocks, unlike Java's `synchronized`. That is another reason to keep guard scopes tiny.
- *[Ownership & moves](01-primer.md#primer-ownership)* `fetched.clone()` goes into both caches, then the original is moved out as the return value on line 285.

`rust/myotis-evm/src/database.rs` · lines 317–350

```rust
impl DatabaseRef for OracleDatabase {
    type Error = OracleError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let addr = address.into_array();
        let over = self.overrides.get(&addr);
        // No override: the ordinary verified path, untouched.
        let Some(over) = over else {
            return Ok(self.account(addr)?.as_ref().map(to_account_info));
        };
        // With an override the account EXISTS even if the chain has no such
        // account (geth does the same) — otherwise a call to an address that
        // only exists as a hypothesis could not run at all, which is exactly
        // the deployless-helper pattern wallets use.
        //
        // A field the caller did not override still comes from verified state,
        // so the fetch is still needed — except when `code` alone is given for
        // an absent account, where there is nothing to fall through to.
        let base = self.account(addr)?;
        let mut info = base.as_ref().map(to_account_info).unwrap_or_default();
        if let Some(balance) = over.balance {
            info.balance = balance;
        }
        if let Some(nonce) = over.nonce {
            info.nonce = nonce;
        }
        if let Some(code) = &over.code {
            // Set BOTH: revm may execute the inline code directly, or resolve it
            // by hash through `code_by_hash_ref` (which also honours overrides).
            info.code_hash = B256::from(myotis_core::keccak::keccak256(code));
            info.code = Some(to_bytecode(code.clone().into()));
        }
        Ok(Some(info))
    }
```

> [!TIP]
> **Why `DatabaseRef` and not `Database`**
>
> revm's `Database` trait takes `&mut self`; `DatabaseRef` has the same methods on `&self`, and revm implements it for `&T` and `Arc<T>` too. With `&self`, the executor keeps ownership of *one* database and *lends* it to every loop iteration, so everything learned in iteration 1 is still there in iteration 2. The price is what you saw above: internal state must use interior mutability. `type Error = OracleError;` is an **associated type**: each implementor picks its own error type.

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let Some(over) = over else { return …; };` (line 324) is **let-else**: bind the pattern or run the `else` block, which must leave the function. `over` is an `Option<&AccountOverride>` borrowed from `self.overrides`, so nothing is copied.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* `self.account(addr)?.as_ref().map(to_account_info)`: `as_ref` turns `Option<OracleAccount>` into `Option<&OracleAccount>`, which matches `to_account_info(acc: &OracleAccount)`, and the function's name is passed where a closure would go.
- *[Protocol & domain](01-primer.md#primer-domain)* An override makes the account *exist* even when the chain has none (geth does the same), which is how a wallet runs a helper contract it never deployed. Overridden code sets both `code_hash` and `code`, because revm may run the inline code or look it up by hash.

#### BLOCKHASH from verified data

The call runs on block N's post-state, so `BLOCKHASH(k)` is defined for N−256 ≤ k &amp;lt; N and zero elsewhere. Before #664 the adapter refused every `BLOCKHASH`. Now it answers from three proven sources:

| Block k | Source | When it cannot be proven |
|---|---|---|
| outside the window | zero, by the opcode's definition | (always answerable) |
| N−1 | the header's `parentHash` | `BlockHashUnsupported` when the context has none |
| from Prague on | the EIP-2935 history contract's storage at slot `k % 8191`, read like any `SLOAD` (proven, cached by root, prefetched in waves) | a zero slot means “never written”, so it falls through to the walk |
| otherwise | a header walk down from N−1, proven by `SnapStateOracle::fetch_block_hash` | `BlockHashUnavailable` (retryable), or `BlockHashUnsupported` without a parent hash |

`rust/myotis-evm/src/database.rs` · lines 418–454

```rust
fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
    let Some(source) = self.block_hashes else {
        return Err(OracleError::BlockHashUnsupported { number });
    };
    // Outside the opcode's window the answer is zero by definition (revm
    // already pushes zero there without asking; kept here so the adapter
    // is right on its own).
    if number >= source.number || source.number - number > BLOCKHASH_WINDOW {
        return Ok(B256::ZERO);
    }
    let parent = source.number - 1;
    if number == parent {
        return source
            .parent_hash
            .map(B256::from)
            .ok_or(OracleError::BlockHashUnsupported { number });
    }
    if source.history_contract {
        let slot = U256::from(number % HISTORY_SERVE_WINDOW);
        let misses = self.track.lock().unwrap().misses;
        let stored = self.verified_storage(HISTORY_STORAGE_ADDRESS, slot)?;
        // In window, a written slot holds exactly block `number`'s hash —
        // it is overwritten only 8191 blocks later.
        if stored != U256::ZERO {
            return Ok(B256::from(stored.to_be_bytes::<32>()));
        }
        // A discovery pass's placeholder (counted, and the slot is in the
        // access set for the wave): the real run reads the slot, so no
        // walk now.
        if self.track.lock().unwrap().misses != misses {
            return Ok(B256::ZERO);
        }
        // A proven zero: a slot the ring never wrote.
    }
    let anchor = source.parent_hash.ok_or(OracleError::BlockHashUnsupported { number })?;
    self.walked_block_hash(parent, &anchor, number).map(B256::from)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* Line 419, `let Some(source) = self.block_hashes else { … }`: the method has only `&self`, and you cannot move a field out of a borrow. This compiles because `BlockHashes` derives `Copy` (line 70), so the pattern *copies* the 32-byte hash, the number and the flag into `source`. Remove `Copy` from the derive and the line fails with “cannot move out of `self.block_hashes`”.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* Line 437 copies the miss counter (`u64`) out and drops the guard at the `;`. Line 447 compares it with a fresh read. If the counter moved, the zero on line 438 was a discovery-pass placeholder: the slot is already in the access set, the next wave fetches it, and the real run will read the true value. If it did not move, the zero is proven, and the walk runs.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* Line 438's `?` propagates an `InvalidProof` on the history slot. It does *not* fall back to the header walk: a failed proof is an attack signal, not a gap to paper over. The test `a_history_value_that_fails_its_proof_fails_the_call` in [the BLOCKHASH tests](#f-myotis-evm-src-executor-tests-blockhash-rs) pins exactly this.

*[Result, ? and panics](01-primer.md#primer-error-handling)* Also in this file: the access set is gas-bounded (a 30 M run touches at most about 14k slots, says the `AccessSet` doc). `verified_storage` (lines 460–493) is the three-tier slot read without overrides; `BLOCKHASH` uses it so a caller's override of the history contract cannot change a block hash, since `BLOCKHASH` reads the chain, not the hypothesis. Bytecode is re-hashed after the oracle's own check, so it is verified twice. `to_bytecode` (lines 300–302) loads bytecode starting with `0xEF01` that is not a valid EIP-7702 delegation as legacy code instead of calling revm's panicking constructor; under the workspace's `panic = "abort"` a panic would kill the host.

> [!WARNING]
> **Stale or inaccurate comments**
>
> The `ViewCache` doc (lines 94–98) says in-flight deduplication “arrives with the async prefetch layer (a later Milestone-C slice)”. The prefetch layer (`prefetch_batch`) exists now; whether it deduplicates in flight is decided in `myotis-net`, not here, so the sentence is at least out of date. The module doc's “three tiers” (line 5) leaves out the override layer, which the struct doc on line 171 describes.

<a id="f-myotis-evm-src-overrides-rs"></a>

### myotis-evm/src/overrides.rs

*library · 165 lines*

`eth_call` state overrides: caller-supplied code, balance, nonce or storage, layered over verified state for exactly one call. The doc explains why this is not a hole in the trust model (the answer is explicitly hypothetical, and is never cached or persisted) and why it is needed. Ambire and Kohaku call undeployed helper contracts, and issue #314 was an engine that silently ignored the parameter and gave plausible wrong answers. That incident is the origin of the “apply or refuse, never silently ignore” rule in `CLAUDE.md`.

`rust/myotis-evm/src/overrides.rs` · lines 32–56

```rust
/// One account's override. Every field is optional; an all-`None` entry still
/// forces the account to EXIST (geth does the same), which matters for a call
/// to an address that has no on-chain account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountOverride {
    pub code: Option<Vec<u8>>,
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    /// Full storage replacement — unlisted slots read as zero.
    pub state: Option<HashMap<U256, U256>>,
    /// Per-slot overlay; unlisted slots fall through to verified state.
    pub state_diff: HashMap<U256, U256>,
}

impl AccountOverride {
    /// The value this override dictates for `slot`, and whether it is
    /// authoritative. `Some(v)` = use `v` and do NOT consult the chain;
    /// `None` = fall through.
    pub fn storage(&self, slot: U256) -> Option<U256> {
        if let Some(full) = &self.state {
            // Full replacement: an absent slot is zero, not a fall-through.
            return Some(full.get(&slot).copied().unwrap_or(U256::ZERO));
        }
        self.state_diff.get(&slot).copied()
    }
```

`rust/myotis-evm/src/overrides.rs` · lines 95–103

```rust
/// Overridden code whose keccak matches `hash`, if any. revm resolves code
/// by hash when an `AccountInfo` carries one, so an overridden account's
/// bytecode has to be reachable that way too.
pub fn code_by_hash(&self, hash: &[u8; 32]) -> Option<&[u8]> {
    self.accounts.values().find_map(|a| {
        let code = a.code.as_deref()?;
        (myotis_core::keccak::keccak256(code) == *hash).then_some(code)
    })
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `state: Option<HashMap<…>>` separates “not given” from “given but empty”, which geth treats differently (empty means every slot is zero).
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* `code_by_hash(&self, …) -> Option<&[u8]>`: elision ties the result to `&self`. The returned slice points into a `Vec` the overrides own, and nothing is copied.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* `find_map` with a `?` *inside the closure*: the `?` leaves only the closure (returning `None` for that account), not the method. `.then_some(code)` is fine here because `code` is already computed and cheap.

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* New since September: `sorted()` (lines 89–93) returns `Vec<(&[u8; 20], &AccountOverride)>`, references into the map, ordered by address, because geth applies overrides in that order. `sort_by(|a, b| a.0.cmp(b.0))` compares byte arrays, which implement `Ord` lexicographically. The vector cannot outlive the `StateOverrides` it borrows from.

<a id="f-myotis-evm-src-fork-rs"></a>

### myotis-evm/src/fork.rs

*library · 409 lines · Java twin · EvmFactory fork tables*

Maps `(chain_id, block_number, timestamp)` to revm's `SpecId`, the fork rules, for mainnet, Sepolia, Gnosis and (new) Chiado. Other chains get `UnsupportedChain`. Pre-London blocks on mainnet and pre-Shanghai blocks elsewhere get `ForkTooOld`. Post-Merge forks activate by timestamp, which is checked first. Every table ends at Osaka. Sepolia alone has an Amsterdam date: revm can price Amsterdam, so this table *serves* it, while the Java engine's Besu cannot and *refuses* the same blocks. The tests pin each constant in both decimal and hex, a guard against a past decimal slip on Gnosis.

`rust/myotis-evm/src/fork.rs` · lines 61–76

```rust
/// The revm `SpecId` a `(chain_id, block_number, timestamp)` activates:
/// [`EvmError::UnsupportedChain`] for a chain with no table here,
/// [`EvmError::ForkTooOld`] below each chain's floor.
///
/// The Java `EvmFactory` mirrors this table PER CHAIN (its per-chain cascades
/// and the ChainAwareForkTest are the twins of this function and its tests) —
/// keep the two in lockstep whenever a fork constant is added.
pub fn spec_for(chain_id: u64, block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
    match chain_id {
        1 => mainnet_spec(block_number, timestamp),
        11_155_111 => sepolia_spec(block_number, timestamp),
        100 => gnosis_spec(block_number, timestamp),
        10_200 => chiado_spec(block_number, timestamp),
        other => Err(EvmError::UnsupportedChain { chain_id: other }),
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match` on integers, with `other => …` binding everything else. `11_155_111` uses digit separators. The `match` is the function's value, with no `return`. Each per-chain function (lines 80–184) is an `if`/`else if` chain that is itself the tail expression; in three of them the newest rung (Osaka, or Amsterdam on Sepolia) is checked first with an early `return`.

> [!WARNING]
> **Stale or inaccurate comments**
>
> The module doc (lines 7–8) says “Everything below London throws”. That is true for mainnet only; the other three chains fail below Shanghai.

<a id="f-myotis-evm-src-executor-rs"></a>

### myotis-evm/src/executor.rs

*library · 4,508 lines · Java twin · PrefetchingEvmExecutor*

`EvmExecutor` is the public entry point to the EVM. Each request runs against a fresh `OracleDatabase`, and nothing is committed. A view call runs with revm's transaction-level checks switched off (balance, nonce, base fee, EIP-3607, block gas limit) because it is not a real transaction; the transaction-object entry points put geth's checks back themselves, before the run, in geth's order and geth's words. The call is non-static, so a simulated `SSTORE` is journaled and discarded. Of its 4,508 lines, the first 1,666 are code and the rest are tests.

| Lines | What happens |
|---|---|
| 1–47 | Module docs and imports. |
| 49–183 | `RequestInspector`: revm's per-instruction hook. Cancellation, discovery bookkeeping, and the access-list, trace and simulation recorders. |
| 185–302 | `AccessListRecorder` (geth's access-list tracer), `CreatedAccessList`, `ACCESS_LIST_ROUNDS` = 10. |
| 304–371 | Constants: `VIEW_CALL_GAS` = 30 M, `PREFETCH_ITERATION_CAP` = 12, the 21,000 transfer, the call stipend, the 1.5 % search ratio, the precompile range, the zero-address view caller. |
| 373–411 | The struct, `CallCost`, `new`, `cost`. |
| 413–501 | The view-call API: `call_view`, `call_view_from`, `call_view_overridden`, `create_view`, `estimate_gas`. |
| 503–722 | `estimate_tx`: the ceiling, the fee and funds checks, the 21,000 shortcut (before Amsterdam only), the run, and geth's search for the lowest working gas limit. |
| 724–836 | `call_tx`, `run_tx` (fixture-only), `call_tx_capped`, `prepare_tx_call`. |
| 838–934 | `create_access_list`: trace, rerun with the list, repeat until it stops changing. |
| 936–1044 | `trace_call` (call tracer and prestate tracer; [stop 8](08-evm-sim.md)), `delegate_of`. |
| 1046–1122 | `database_for_with`, `execute_with_db`, `execute_recording`: one revm run. |
| 1124–1231 | The view-call path into the loop: `call`, `call_capped(_with)`, `run_converged`, `converge` (primes the target). |
| 1233–1379 | The prefetch convergence loop: `converge_runs`, `prefetch_wave`, `first_wave`. |
| 1381–1607 | Free helpers: error wording, `spec_for_context` (the `SLOTNUM` refusals), `view_cfg`, `tx_env`, `check_tx`, `check_fee_cap`, `buy_gas_shortfall`, `with_sender_nonce`. |
| 1609–1665 | `output_bytes`, the 1.15 buffer, `map_halt`, `map_evm_error`, a compile-time assertion. |
| 1667–1716 | Tests: imports, the two submodule files (`relay_adapt_7702_shield` in [stop 8](08-evm-sim.md), `blockhash` below), cancellation. |
| 1717–2098 | Tests: overrides and creation, opcodes, reverts, out of gas, the 21,000 shortcut. |
| 2099–2642 | Tests: the convergence loop and its waves (#532). |
| 2644–3139 | Tests: estimates, the gas search, EIP-7702 authorizations, access lists in estimates. |
| 3140–3426 | Tests: `trace_call`, including goldens from a full node's call tracer. |
| 3428–3637 | Tests: `create_access_list`. |
| 3639–3867 | Tests: estimate ceilings, fee caps, the Osaka transaction cap, refused requests. |
| 3869–4189 | Tests: `call_tx` over the full transaction object (#509). |
| 4191–4508 | Tests: chains, Amsterdam and `SLOTNUM`, the fork floor, an absent target. |

#### The inspector: one hook, several recorders

`rust/myotis-evm/src/executor.rs` · lines 49–73

```rust
/// The accounts whose code a discovery pass needed (see [`RequestInspector`]).
pub(crate) type CodeNeeded = std::cell::RefCell<std::collections::HashSet<[u8; 20]>>;

pub(crate) struct RequestInspector<'a> {
    pub(crate) oracle: &'a dyn SnapStateOracle,
    /// Records, during a discovery pass, the accounts whose code the run
    /// needed: the account each call runs the code of
    /// (`CallInputs::bytecode_address`), and the one an `EXTCODESIZE` or
    /// `EXTCODECOPY` inspects. Solidity guards a call to a contract with an
    /// `EXTCODESIZE`, and against a placeholder (no code) that guard fails
    /// before the call runs, so the target shows there a pass earlier. The
    /// pass's wave fetches the code of these and no other (#532 review).
    /// `None` outside discovery passes.
    pub(crate) code_needed: Option<&'a CodeNeeded>,
    /// Records, for `eth_createAccessList`, every address and storage key the
    /// run touches ([`AccessListRecorder`]). `None` on every other run.
    pub(crate) access_list: Option<&'a AccessListRecorder>,
    /// Records, for `debug_traceCall`, the tracer's view of the run
    /// ([`TraceRecorder`]). `None` on every other run.
    pub(crate) trace: Option<&'a TraceRecorder>,
    /// Records, for `eth_simulateV1`, each call's logs and transfers and
    /// stops a run that reads what the simulation cannot serve
    /// ([`SimRecorder`]). `None` on every other run.
    pub(crate) sim: Option<&'a SimRecorder>,
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* Every field is a *borrowed* reference. `&'a dyn SnapStateOracle` is a trait object behind a plain reference, not an `Arc`: the inspector never owns the oracle. The lifetime `'a` proves the inspector, and therefore the EVM that owns it, cannot outlive the things it points at. `Option<&'a T>` is the idiomatic “maybe a recorder”: it is pointer-sized (Rust uses the null value for `None`) and `Copy`.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `CodeNeeded` (line 50) is a type alias for `RefCell<HashSet<[u8; 20]>>`. The inspector holds only a shared `&CodeNeeded`, yet inserts into it: `RefCell` moves the borrow check to run time (`borrow_mut()` panics if another borrow is active). It is enough here because one EVM run happens on one thread. The database needs a `Mutex` for the same job because its type must be `Sync`; a `RefCell` is never `Sync`, so the compiler would refuse to share it across threads.

`rust/myotis-evm/src/executor.rs` · lines 84–123

```rust
impl<CTX: ContextTr> Inspector<CTX> for RequestInspector<'_> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        if self.oracle.check_request().is_err() {
            interp.bytecode.set_action(InterpreterAction::Return(InterpreterResult {
                result: InstructionResult::Stop,
                output: Default::default(),
                gas: interp.gas,
            }));
            return;
        }
        if let Some(sim) = self.sim {
            if sim.step(interp) {
                // A read the simulation refuses: stop here, and every frame
                // above stops at its next step (the run is refused).
                interp.bytecode.set_action(InterpreterAction::Return(InterpreterResult {
                    result: InstructionResult::Stop,
                    output: Default::default(),
                    gas: interp.gas,
                }));
                return;
            }
        }
        if let Some(code_needed) = self.code_needed {
            let opcode = interp.bytecode.opcode();
            if opcode == revm::bytecode::opcode::EXTCODESIZE || opcode == revm::bytecode::opcode::EXTCODECOPY {
                if let Ok(word) = interp.stack.peek(0) {
                    let word = word.to_be_bytes::<32>();
                    let mut address = [0u8; 20];
                    address.copy_from_slice(&word[12..]);
                    code_needed.borrow_mut().insert(address);
                }
            }
        }
        if let Some(recorder) = self.access_list {
            recorder.record(interp);
        }
        if let Some(trace) = self.trace {
            trace.step(interp);
        }
    }
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `impl<CTX: ContextTr> Inspector<CTX> for RequestInspector<'_>` is generic over revm's context type, and `'_` says “some lifetime, I don't need to name it”. `step` runs before every instruction.
- *[Protocol & domain](01-primer.md#primer-domain)* **Cancellation per instruction.** If the oracle says the request is cancelled, `set_action` makes the interpreter return with `Stop`, even mid-way through a loop that reads only cached state. The executor checks again after the run (line 1120), so the stop surfaces as `Cancelled`, not as a short answer.
- *[Protocol & domain](01-primer.md#primer-domain) · [Borrowing & slices](01-primer.md#primer-borrowing)* **What code did the run need?** On a discovery pass, `EXTCODESIZE` and `EXTCODECOPY` record the inspected address (its low 20 bytes of the stack's top word), and the `call` hook (line 127) records each call's code address. Solidity guards a call with an `EXTCODESIZE`, and against a placeholder (no code) that guard fails before the call runs, so the target shows up here one pass earlier. `if let Some(code_needed) = self.code_needed` copies the `Option<&…>` out of `&mut self`, which is fine because it is `Copy`.

`rust/myotis-evm/src/executor.rs` · lines 373–411

```rust
/// Executes view calls against verified state. Owns the shared cross-call caches,
/// so repeated calls (e.g. a MetaMask number-pinned retry) reuse verified facts.
pub struct EvmExecutor {
    pub(crate) oracle: Arc<dyn SnapStateOracle>,
    proof_cache: Arc<dyn StateProofCache>,
    bytecode_cache: Arc<dyn BytecodeCache>,
    /// EVM runs so far (for [`Self::cost`]).
    pub(crate) runs: std::sync::atomic::AtomicU64,
}

/// What the calls through one executor cost (#532): its EVM runs, and its
/// state reads on the wire as the oracle measured them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CallCost {
    pub evm_runs: u64,
    pub wire: crate::oracle::WireCost,
}

impl EvmExecutor {
    pub fn new(
        oracle: Arc<dyn SnapStateOracle>,
        proof_cache: Arc<dyn StateProofCache>,
        bytecode_cache: Arc<dyn BytecodeCache>,
    ) -> EvmExecutor {
        EvmExecutor {
            oracle,
            proof_cache,
            bytecode_cache,
            runs: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// What the calls through this executor have cost so far (#532).
    pub fn cost(&self) -> CallCost {
        CallCost {
            evm_runs: self.runs.load(std::sync::atomic::Ordering::Relaxed),
            wire: self.oracle.wire_cost(),
        }
    }
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* `runs: AtomicU64` counts EVM runs behind `&self`. An atomic is the cheapest interior mutability for a single number, like Java's `AtomicLong`. `Ordering::Relaxed` guarantees only that the count itself is not torn or lost; it orders nothing else, which is enough for a statistic. `cost()` returns `CallCost` by value: it derives `Copy`, so the caller gets its own snapshot. The host logs this per call (#532).

#### One run

`rust/myotis-evm/src/executor.rs` · lines 1083–1122

```rust
#[allow(clippy::too_many_arguments)]
fn execute_recording(
    &self,
    db: &OracleDatabase,
    spec: SpecId,
    tx: &TxRequest,
    gas_limit: u64,
    ctx: &BlockContext,
    code_needed: Option<&CodeNeeded>,
    recorders: Recorders<'_>,
) -> Result<ExecutionResult, EvmError> {
    self.oracle.check_request()?;
    self.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let cfg = view_cfg(spec, ctx.chain_id);
    let tx = tx_env(tx, gas_limit, ctx.chain_id)?;
    if let Some(recorder) = recorders.access_list {
        recorder.reset();
    }
    if let Some(recorder) = recorders.trace {
        recorder.reset();
    }

    let mut evm = Context::mainnet()
        .with_ref_db(db)
        .with_block(ctx.block_env())
        .with_cfg(cfg)
        .build_mainnet_with_inspector(RequestInspector {
            oracle: self.oracle.as_ref(),
            code_needed,
            access_list: recorders.access_list,
            trace: recorders.trace,
            sim: None,
        });

    let result = evm.inspect_tx(tx);
    // Cancellation takes precedence over an interpreter stop (including a
    // cancelled nested call) or a just-finished indivisible precompile.
    self.oracle.check_request()?;
    Ok(result.map_err(map_evm_error)?.result)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* Line 1097 *shadows* the parameter: `let tx = tx_env(tx, …)?;` builds revm's `TxEnv` from the borrowed `&TxRequest` and reuses the name. From there on `tx` means the owned `TxEnv`, which line 1117 moves into `inspect_tx`. Kotlin allows a similar pattern only in nested scopes; Rust allows it in the same block.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* `Context::mainnet().with_ref_db(db).with_block(…).with_cfg(cfg)…` is a consuming builder: each call takes the builder by value and returns a new one. The EVM *borrows* the database (`db: &OracleDatabase`) and, through the inspector, the oracle (`self.oracle.as_ref()` borrows a plain `&dyn SnapStateOracle` out of the `Arc`), so it cannot escape this function. `cfg` and the block env are *moved* in. `let mut evm` is needed because `inspect_tx` takes `&mut self`.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* Line 1121, `Ok(result.map_err(map_evm_error)?.result)`, converts revm's error type, propagates it with `?`, and keeps only the `.result` field. A success, a revert and a halt all come back as `Ok(ExecutionResult)`; each caller decides what they mean.
- *[Protocol & domain](01-primer.md#primer-domain)* `view_cfg` (lines 1439–1458) builds the config: revm's per-spec defaults, Amsterdam's two gas-model flags set to exactly “is this Amsterdam”, the five relaxations, and `tx_gas_limit_cap = Some(VIEW_CALL_GAS)` so the Osaka per-transaction cap (224) does not clip a 30 M view call. `tx_env` (lines 1465–1527) always sets the node's chain id; a comment records the live bug where revm's default (mainnet) rejected every call on Sepolia.

#### The prefetch convergence loop

![Prefetch loop. Run revm, in sentinel mode while still discovering, where missing state becomes a counted zero placeholder. A sentinel run that handed out no placeholder and did not fail is the answer at once. Otherwise diff the accessed state against what was already seen. If nothing new was touched, a real run returns its answer and a sentinel run ends discovery. Otherwise fetch all fresh reads, plus the code of contracts the run called or inspected, in one parallel verified wave into the shared caches, and run again. At most twelve iterations; discovery also ends at the oracle's time bound or two runs before the cap. Hitting the cap fails with IterationLimitExceeded.](img/07-evm-1.svg)

*Sentinel runs discover which state a call needs without waiting on the network, so the unknown reads can be fetched as *one* parallel wave instead of one round-trip per `SLOAD`. Answers only ever come from a real run, or from a sentinel run that read nothing unverified.*

Before the loop, `converge` (lines 1208–1231) primes the target's account and code with sentinel off, so the first pass runs the real top-level code. The transaction-object entry points also make a `first_wave` (lines 1373–1378): the sender, the target and each EIP-7702 delegate, plus their code, in one batch. A discovery pass would otherwise see a delegate only one pass late. Why 12 and not 4? The constant's doc (lines 320–329) gives the measurement: a wallet's recorded RelayAdapt7702 shield transaction made 48 of its 57 reads one round-trip at a time behind the old cap of four.

`rust/myotis-evm/src/executor.rs` · lines 1240–1263

```rust
pub(crate) fn converge_runs<T>(
    &self,
    db: &OracleDatabase,
    ctx: &BlockContext,
    cap: usize,
    mut run: impl FnMut(Option<&CodeNeeded>) -> Result<T, EvmError>,
) -> Result<T, EvmError> {
    let mut seen = AccessSet::default();
    let mut discovering = true;
    for iter in 0..cap {
        self.oracle.check_request()?;
        // Sentinel while still discovering, but the LAST TWO iterations are
        // always real (one final wave + one warm real run). The oracle
        // bounds discovery in time (`keep_discovering`; #532 review): this
        // crate holds no clock. Discovery passes are the loop's first
        // iterations, so `iter` numbers them.
        discovering = discovering && iter + 2 < cap && self.oracle.keep_discovering(iter);
        let sentinel = discovering;
        db.set_sentinel(sentinel);
        let misses_before = db.sentinel_misses();
        let code_needed = CodeNeeded::default();
        let outcome = run(sentinel.then_some(&code_needed));
        db.set_sentinel(false);
        let fresh = db.take_access_set().minus(&seen);
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `converge_runs<T>` takes the run as `mut run: impl FnMut(Option<&CodeNeeded>) -> Result<T, EvmError>`. `FnMut` means the closure may mutate what it captured, so calling it needs `&mut` access, hence `mut run`. The loop does not care what a run is: for a call it is one transaction, for `eth_simulateV1` ([stop 8](08-evm-sim.md)) a whole simulated block sequence. Both go through the same `db`, so the access set is the run's.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `let code_needed = CodeNeeded::default();` is a fresh, owned set per iteration. `sentinel.then_some(&code_needed)` lends it to the run only on a discovery pass. The loan ends when `run` returns; nothing in `T` can hold on to it, because the closure's argument lifetime is chosen per call.
- *[Protocol & domain](01-primer.md#primer-domain)* Line 1256: `discovering` can only go from true to false. The `&&` short-circuits, so `keep_discovering` is not even asked once discovery has ended. `iter + 2 < cap` reserves the last two iterations for real runs.

`rust/myotis-evm/src/executor.rs` · lines 1265–1310

```rust
        if sentinel {
            // A sentinel run that discovered nothing new AND handed out no
            // placeholder was all verified hits — byte-identical to a real
            // run: return it (the hit-only fast path). A sentinel failure
            // (zeroes tripping a require()) is tolerated; its partial
            // access set still drives the wave.
            //
            // Two deliberate deviations from Java here: (1) the access diff
            // includes CODE hashes (Java diffs only accounts+slots) — a
            // code-only discovery keeps the wave warm instead of going
            // serial, and determinism over verified state still guarantees
            // convergence; (2) a hit-only run's REVERT returns immediately
            // (Java re-derives the identical revert from the next real run
            // — all-verified reads make the outcome deterministic, so this
            // is the same answer one iteration sooner).
            // A pass that handed out no placeholder read only verified
            // state: it IS a real run, whatever it touched, so a warm call
            // ends here instead of making a real run and an empty wave
            // (#532 review).
            if db.sentinel_misses() == misses_before {
                if let Ok(result) = outcome {
                    return Ok(result);
                }
            }
            if fresh.is_empty() {
                discovering = false;
            } else {
                self.prefetch_wave(ctx, &fresh, &code_needed.into_inner());
                seen.merge(fresh);
            }
        } else {
            // Real-run outcomes are authoritative: errors (incl. reverts —
            // they ARE the answer, callers key on the revert data) propagate.
            let result = outcome?;
            if fresh.is_empty() {
                return Ok(result); // converged
            }
            // Still discovering under real mode (a sentinel zero had hidden
            // a branch): warm the stragglers and run again. No code to
            // follow: the next run is real and reads what this one did.
            self.prefetch_wave(ctx, &fresh, &Default::default());
            seen.merge(fresh);
        }
    }
    Err(EvmError::IterationLimitExceeded { cap })
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability)* Every `db.*` call uses a *shared* reference, yet changes the database's sentinel flag, counters and access set. This is interior mutability as an API style.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* Lines 1292–1293: `self.prefetch_wave(ctx, &fresh, &code_needed.into_inner());` *borrows* `fresh`, then `seen.merge(fresh);` *moves* it. Swap the two lines and the compiler reports “borrow of moved value”. `code_needed.into_inner()` consumes the `RefCell` and returns the `HashSet` it held; that is allowed only because the run's loan of `code_needed` has ended.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* A selective `?`: a real run's error propagates (`outcome?`, line 1298), while a sentinel run's error is tolerated. Zero placeholders can legitimately trip a `require()`.
- *[Protocol & domain](01-primer.md#primer-domain)* Lines 1284–1288 are the hit-only fast path: a discovery pass that handed out no placeholder read only verified state, so it *is* a real run and is returned at once. A warm call is therefore exactly one EVM run and no wave (the test `a_warm_call_is_its_one_discovery_pass` pins it).

`rust/myotis-evm/src/executor.rs` · lines 1318–1341

```rust
pub(crate) fn prefetch_wave(&self, ctx: &BlockContext, fresh: &AccessSet, code_needed: &std::collections::HashSet<[u8; 20]>) {
    let root = &ctx.state_root;
    let batch = |accounts: &[([u8; 20], Vec<U256>)], code_hashes: &[[u8; 32]]| {
        if !accounts.is_empty() || !code_hashes.is_empty() {
            self.oracle.prefetch_batch(root, accounts, code_hashes, &*self.proof_cache, &*self.bytecode_cache);
        }
    };
    let mut by_account: std::collections::HashMap<[u8; 20], Vec<U256>> =
        std::collections::HashMap::new();
    for addr in &fresh.accounts {
        by_account.entry(*addr).or_default();
    }
    for (addr, slot) in &fresh.slots {
        if self.proof_cache.get_storage(root, addr, slot).is_none() {
            by_account.entry(*addr).or_default().push(*slot);
        }
    }
    let items: Vec<([u8; 20], Vec<U256>)> = by_account
        .into_iter()
        .filter(|(addr, slots)| !slots.is_empty() || self.proof_cache.get_account(root, addr).is_none())
        .collect();
    let code_hashes: Vec<[u8; 32]> =
        fresh.code_hashes.iter().copied().filter(|hash| self.bytecode_cache.get(hash).is_none()).collect();
    batch(&items, &code_hashes);
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let batch = |accounts, code_hashes| { … }` captures `self` and `root` by shared reference. It only reads them, so it is an `Fn` closure and can be called twice (lines 1341 and 1362). A Kotlin lambda does the same, but there the compiler does not check that the captured objects outlive it.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `&*self.proof_cache`: `*` dereferences the `Arc<dyn StateProofCache>` to the `dyn StateProofCache` inside, and `&` borrows it again as the `&dyn StateProofCache` the oracle method wants. No reference count changes.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `by_account.entry(*addr).or_default().push(*slot)` is the entry API: find or insert an empty `Vec`, then push. `by_account.into_iter()` consumes the map, so the filtered pairs are moved into `items`, not copied. What the caches already hold is left out, and an empty wave is not sent.

*[Protocol & domain](01-primer.md#primer-domain)* The rest of `prefetch_wave` (lines 1342–1362) is the code-following step: for each account the wave fetched whose code the pass needed (from `code_needed`), it fetches that code too, in a second batch. A newly reached contract then runs in the next pass instead of costing one pass just to learn its code hash. An account that was only read (`BALANCE`, `EXTCODEHASH`) is not followed.

#### Transaction objects and the gas search

`rust/myotis-evm/src/executor.rs` · lines 800–836

```rust
fn prepare_tx_call(
    &self,
    tx: &TxRequest,
    ctx: &BlockContext,
    overrides: StateOverrides,
) -> Result<(SpecId, OracleDatabase, u64), EvmError> {
    self.oracle.check_request()?;
    let spec = spec_for_context(ctx)?;
    check_tx(tx, ctx, spec)?;
    // Refusals of the request itself first — a nonce contradicting the
    // override included — exactly as for an estimate.
    let db = self.database_for_with(ctx, with_sender_nonce(overrides, tx)?);
    let gas_limit = tx.gas.map_or(VIEW_CALL_GAS, |gas| gas.min(VIEW_CALL_GAS));
    let supplied = |error: EvmError| supplied_gas(gas_limit, error);
    check_fee_cap(tx, ctx).map_err(supplied)?;
    // The rest read state (the sender's balance below, the target in the
    // loop's prime), so the first wave goes here, as for an estimate (#532
    // review).
    self.first_wave(ctx, tx);
    // geth's buyGas, fee or no fee. Checked here, not by revm: its own
    // balance check would read a prefetch placeholder on a discovery pass,
    // and here the read also primes the sender before the first pass.
    if let Some(short) = buy_gas_shortfall(&db, tx, gas_limit)? {
        return Err(supplied(short));
    }
    let fee_cap = tx.fees.fee_cap();
    // revm prices the run as `gas × price` in u128 and `expect`s it not to
    // overflow — with its own balance check off nothing else stops it, and
    // a panic aborts the host. Only a balance overridden past 2^128 wei
    // gets here with such a price: nothing on chain can pay it.
    if u128::from(gas_limit).checked_mul(fee_cap).is_none() {
        return Err(EvmError::InvalidRequest {
            detail: format!("gas × fee cap ({gas_limit} × {fee_cap}) exceeds the 2^128 wei this engine can price"),
        });
    }
    Ok((spec, db, gas_limit))
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* The function returns `(SpecId, OracleDatabase, u64)`. The database is created on line 811 and *moved* out to the caller in the tuple on line 835, so `call_tx_capped`, `create_access_list_within` and `trace_call` each own the one database their runs share.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Ownership & moves](01-primer.md#primer-ownership)* Line 813, `let supplied = |error: EvmError| supplied_gas(gas_limit, error);`, captures `gas_limit` by reference. A closure whose captures are all `Copy` is itself `Copy`, and a shared reference is `Copy`. That is why `map_err(supplied)` on line 814, which takes the closure by value, does not use it up, and line 823 can call it again.
- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* The order is geth's: request refusals (`check_tx`, a nonce contradicting an override), the fee cap against the base fee, then `buyGas` (the sender must hold `gas × fee cap + value`). Lines 830–834 refuse a price revm cannot represent: revm computes `gas × price` in `u128` and `expect`s no overflow, and with its balance check off nothing else stops a state override from getting there. A panic would abort the host.

`rust/myotis-evm/src/executor.rs` · lines 669–703

```rust
fn lowest_working_limit(
    &self,
    db: &OracleDatabase,
    spec: SpecId,
    tx: &TxRequest,
    ctx: &BlockContext,
    drawn: u64,
    mut hi: u64,
) -> Result<u64, EvmError> {
    let mut lo = drawn.saturating_sub(1);
    let optimistic = (drawn + CALL_STIPEND) * 64 / 63;
    if optimistic < hi {
        if self.succeeds_with(db, spec, tx, ctx, optimistic)? {
            hi = optimistic;
        } else {
            lo = optimistic;
        }
    }
    while lo + 1 < hi {
        // Within the error ratio of the answer: a wallet bumps the limit
        // anyway, and every probe is a full run.
        let (num, den) = ESTIMATE_ERROR_RATIO;
        if u128::from(hi - lo) * den < u128::from(hi) * num {
            break;
        }
        // Skewed low: most transactions need little more than they drew.
        let mid = ((hi + lo) / 2).min(lo.saturating_mul(2));
        if self.succeeds_with(db, spec, tx, ctx, mid)? {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Ok(hi)
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Protocol & domain](01-primer.md#primer-domain)* `mut hi: u64` in the parameter list: an integer argument is copied in, and `mut` lets the function change its own copy. The caller's value is untouched. The algorithm is geth's estimator: a first “optimistic” probe at what the run drew plus the call stipend, times 64/63 (a nested call withholds 1/64 of its gas), then a bisection skewed low that stops within 1.5 %. Each probe (`succeeds_with`) is a full EVM run against the same database, so it reads only cached, verified state. `estimate_tx` (lines 521–647) then adds the 1.15 buffer and never answers above the ceiling. Before Amsterdam, an empty-calldata transfer to a codeless, non-precompile account is still exactly 21,000 with no run and no buffer; from Amsterdam on (EIP-2780, EIP-8037) that shortcut would be wrong, so the search prices it.

`rust/myotis-evm/src/executor.rs` · lines 1592–1607

```rust
fn with_sender_nonce(mut overrides: StateOverrides, tx: &TxRequest) -> Result<StateOverrides, EvmError> {
    let Some(nonce) = tx.nonce else {
        return Ok(overrides);
    };
    let mut entry = overrides.get(&tx.from).cloned().unwrap_or_default();
    if let Some(overridden) = entry.nonce.filter(|n| *n != nonce) {
        return Err(EvmError::InvalidRequest {
            detail: format!(
                "nonce {nonce} contradicts the state override's nonce {overridden} for the sender"
            ),
        });
    }
    entry.nonce = Some(nonce);
    overrides.insert(tx.from, entry);
    Ok(overrides)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* `with_sender_nonce(mut overrides: StateOverrides, …) -> Result<StateOverrides, EvmError>` takes the overrides *by value*, edits them, and hands them back: an owned value passing through a function. The caller writes `with_sender_nonce(overrides, tx)?` and can no longer use the old name, which prevents using a stale copy.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* Line 1596, `overrides.get(&tx.from).cloned().unwrap_or_default()`: `get` returns a reference into the map, and `.cloned()` turns it into an owned `AccountOverride`. Without the clone, `entry` would borrow `overrides` immutably, and the `overrides.insert` on line 1605 (a mutable borrow) would not compile.
- *[Protocol & domain](01-primer.md#primer-domain)* A state override naming a *different* nonce for the sender asks a contradictory question, so it is refused rather than one of the two being picked silently.

#### Guards at the edges

`spec_for_context` (lines 1411–1425) wraps `spec_for` with a pair of refusals for EIP-7843. An Amsterdam-spec context without a slot number would run `SLOTNUM` against a made-up zero, so it is `MissingSlotNumber`. A pre-Amsterdam context *with* a slot number means the network moved the fork after this build shipped, so running it under the older rules would be a well-formed wrong answer: `UnexpectedSlotNumber`. Both happen before any state is read. `map_evm_error` (lines 1633–1658) is generic over revm's database error type `E: DBErrorMarker + Into<EvmError>`, so `EVMError::Database(e) => e.into()` works for whatever the database's error is.

`rust/myotis-evm/src/executor.rs` · lines 1660–1665

```rust
// Ensure the DB error the executor threads is exactly OracleError (a compile-time
// guard: if OracleDatabase's Error type ever diverges, `run` stops compiling).
const _: fn() = || {
    fn assert_db_error<T: DBErrorMarker + Into<EvmError>>() {}
    assert_db_error::<OracleError>();
};
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics)* A **static assertion**: an unnamed constant holding a closure that never runs. The compiler still type-checks it, so if `OracleError` stopped satisfying those bounds, the crate would stop compiling. It has no run-time cost.

> [!WARNING]
> **Stale or inaccurate comments**
>
> Line 1661 says the assertion makes “`run` stop compiling”. No function named `run` exists any more (there is a closure parameter `run` in `converge_runs`, which is not what is meant). The module doc (lines 10–17) says the sender need not “hold a balance, or pay the base fee”; that is true of the view-call family, while the transaction-object family now checks the fee cap and the sender's funds itself. The test `sepolia_context_executes_with_its_chain_id` (line 4208) blames `build_fill()`; the code now uses `build()`, whose own comment (line 1518) is correct.

<a id="f-myotis-evm-src-executor-tests-blockhash-rs"></a>

### myotis-evm/src/executor/tests/blockhash.rs

*unit tests (child module) · 250 lines*

Thirteen tests for `BLOCKHASH` from verified data (#664): the parent hash for N−1, the history contract from Prague on (on mainnet, Sepolia and Gnosis), the header walk before Prague or for a block the ring never held, zero outside the window, and refusals. A test contract built from raw opcodes returns `blockhash(number - d)` for each depth `d`. The `world` helper decides which sources hold which hash, and the answer shows which source ran.

The file is declared as `mod blockhash;` inside `mod tests` in `executor.rs` (line 1679). Because `executor.rs` is not a `mod.rs` file, the compiler looks for its child modules in a directory with its name: `executor/tests/blockhash.rs`. Its first line, `use super::*;`, imports everything visible in the parent test module, including *private* items (child modules may see their ancestors' private items) and the parent's own `use` imports. That is how the file can use `ctx`, `ROOT`, `TARGET`, `PARENT`, the `WaveFilling` oracle, `Arc` and `U256` without importing them.

`rust/myotis-evm/src/executor/tests/blockhash.rs` · lines 152–171

```rust
/// A world whose every proof of the history contract's storage fails.
struct ForgedHistory(FixtureSnapStateOracle);

impl SnapStateOracle for ForgedHistory {
    fn fetch_account(&self, r: &[u8; 32], a: [u8; 20]) -> Result<Option<OracleAccount>, OracleError> {
        self.0.fetch_account(r, a)
    }
    fn fetch_storage(&self, r: &[u8; 32], a: [u8; 20], s: U256) -> Result<U256, OracleError> {
        if a == HISTORY_STORAGE_ADDRESS {
            return Err(OracleError::InvalidProof { state_root: *r, address: a, detail: "forged slot".into() });
        }
        self.0.fetch_storage(r, a, s)
    }
    fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
        self.0.fetch_bytecode(h)
    }
    fn fetch_block_hash(&self, anchor_number: u64, anchor_hash: &[u8; 32], number: u64) -> Result<[u8; 32], OracleError> {
        self.0.fetch_block_hash(anchor_number, anchor_hash, number)
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Tests](01-primer.md#primer-testing)* `struct ForgedHistory(FixtureSnapStateOracle);` is a **newtype**: a one-field tuple struct wrapping another type to give it different behaviour. Each method forwards to `self.0` except `fetch_storage` on the history contract, which reports a failed proof. Rust has no implementation inheritance, so wrapping and forwarding is how you override one method.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Lifetimes](01-primer.md#primer-lifetimes)* The helper above it, `fn exec_over(oracle: impl SnapStateOracle + 'static) -> EvmExecutor` (line 59), accepts any oracle type. `Arc::new(oracle)` then coerces to `Arc<dyn SnapStateOracle>`. The `'static` bound is needed because a `dyn Trait` in an `Arc` means `dyn Trait + 'static` by default: the oracle may not contain short-lived borrows.

<a id="f-myotis-evm-src-ens-name-rs"></a>

### myotis-evm/src/ens/name.rs

*library · 166 lines · Java twin · Namehash / DnsEncoder*

`namehash` (ENSIP-1), `namehash_from` and `dns_encode` (the ENSIP-10 wire format). `namehash_from` is new: it starts the recurrence at a given root node instead of 32 zero bytes, which Genome's `.gno` tree on Gnosis needs. Names are only lowercased; there is no UTS-46 normalisation, a documented gap relative to Java. Trailing dots are treated exactly as Java treats them, which makes such names resolve to “no record”.

`rust/myotis-evm/src/ens/name.rs` · lines 28–68

```rust
pub fn namehash_from(root: &[u8; 32], name: &str) -> [u8; 32] {
    let mut node = *root;
    if name.is_empty() {
        return node;
    }
    // `str::split('.')` keeps empty items (interior AND trailing), matching
    // Java's `split("\\.", -1)`.
    for label in name.to_lowercase().split('.').rev() {
        let label_hash = keccak256(label.as_bytes());
        node = keccak256_concat(&node, &label_hash);
    }
    node
}

/// The ENSIP-10 DNS wire encoding of `name`: each label as `<len><utf8>`,
/// terminated by a `0x00` root byte. The root name encodes as `{0x00}`. Rejects
/// an empty label or a label longer than 63 bytes (a malformed name a gateway
/// would reject anyway). At most ONE trailing dot is stripped (the FQDN root
/// dot), matching the Java `DnsEncoder` — `"x.eth.."` is an empty-label error,
/// not silently trimmed.
pub fn dns_encode(name: &str) -> Result<Vec<u8>, EnsError> {
    let lower = name.to_lowercase();
    let trimmed = lower.strip_suffix('.').unwrap_or(&lower);
    if trimmed.is_empty() {
        return Ok(vec![0x00]);
    }
    let mut out = Vec::new();
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            return Err(EnsError::InvalidName("empty label"));
        }
        if bytes.len() > 63 {
            return Err(EnsError::InvalidName("label exceeds 63 bytes"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0x00);
    Ok(out)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* Line 29: `let mut node = *root;` copies the 32-byte array out of the borrowed `&[u8; 32]`. Arrays of `Copy` elements are `Copy`, so the function works on its own copy and the caller's root is unchanged.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* Line 35: `name.to_lowercase()` creates a *temporary* `String`, and `split('.')` borrows from it. A temporary in a `for` loop's iterator expression lives for the whole loop, so the borrowed labels stay valid.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* Lines 49–50: `trimmed` borrows from `lower`, so `lower` needs its own `let` binding to live long enough. `unwrap_or(&lower)` relies on `&String` automatically coercing to `&str`.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `InvalidName("empty label")` carries a `&'static str`: a literal, with no allocation. `bytes.len() as u8` on line 63 is safe because the length was checked to be ≤ 63 first.

<a id="f-myotis-evm-src-ens-abi-rs"></a>

### myotis-evm/src/ens/abi.rs

*library (private module) · 423 lines · Java twin · AbiEncoder / AbiDecoder*

A small hand-written Solidity ABI codec, covering only what ENS needs. The decoders never panic on untrusted data, and offsets or lengths above 64 MiB are rejected, so a forged length cannot force a giant allocation. The module is private (`mod abi;`), so only `ens` can use it. New since September: encoders for a single `bytes` argument and for no-argument calls, and `decode_u64`, all for the ownership reads below.

`rust/myotis-evm/src/ens/abi.rs` · lines 142–161

```rust
/// Read the 32-byte word at `pos` as a `usize`, or `None` if out of bounds or the
/// value exceeds [`MAX_INDEX`] (so a huge offset/length can't drive an OOB read or
/// allocation).
fn read_index(data: &[u8], pos: usize) -> Option<usize> {
    // Bound-check in the u64 domain BEFORE casting: on a 32-bit target
    // (armeabi-v7a Android), `as usize` would truncate — e.g. 2^32 → 0 — and
    // silently bypass the MAX_INDEX guard.
    let v = word_u64(data, pos)?;
    (v <= MAX_INDEX as u64).then_some(v as usize)
}

/// The 32-byte word at [`pos`] as a `u64`: `None` when the data is short or the
/// high 24 bytes are not zero (a value no index or timestamp here can use).
fn word_u64(data: &[u8], pos: usize) -> Option<u64> {
    let word = data.get(pos..pos.checked_add(32)?)?;
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(word[24..32].try_into().ok()?))
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Borrowing & slices](01-primer.md#primer-borrowing)* `data.get(pos..pos.checked_add(32)?)?` (line 156) uses two `?` in an `Option`-returning function: one for arithmetic overflow, one for an out-of-range slice. `&data[a..b]` would panic instead, and a panic aborts the engine.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Check before casting.** On 32-bit Android (armeabi-v7a), `v as usize` truncates silently (232 → 0) and would bypass the size guard. So the bound is checked while the value is still a `u64`, and `then_some` turns the boolean into `Some(v as usize)` or `None`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `decode_dynamic_bytes` (lines 201–207) ends with `.map(<[u8]>::to_vec)`, which passes a method where a closure would go, like Kotlin's `::toList`.

*[Protocol & domain](01-primer.md#primer-domain)* This file encodes `dnsRecord(bytes32,bytes,uint16)` (selector `0xee8de1f7`), which was copied from the Java engine. It is *not* mainnet PublicResolver's `dnsRecord(bytes32,bytes32,uint16)`; the doc on lines 89–93 says so. The module doc (lines 1–4) still lists only `bytes32`, `bytes4`, `address`, `bool` and `bytes`; the file also handles strings, string arrays and `u64` words.

<a id="f-myotis-evm-src-ens-mod-rs"></a>

### myotis-evm/src/ens/mod.rs

*library · 2,257 lines · Java twin · EnsResolver / ReverseLookup*

Name resolution over verified `eth_call`s: forward records (address, text, contenthash, multicoin, pubkey, ABI, dnsRecord, interface implementer), ownership (registry, registrar, NameWrapper), reverse resolution confirmed by a forward lookup, and the in-EVM half of CCIP-Read (ERC-3668). Like Java, it walks the registry directly instead of using ENS's Universal Resolver. All calls go through the `EthCaller` trait, so the tests need no node. There is no HTTP here: an `OffchainLookup` revert reaches the host as a distinct error, and the host performs the gateway request and calls back.

| Lines | What happens |
|---|---|
| 1–33 | Docs, submodules, imports. |
| 35–121 | Pinned addresses: the ENS registry, the Universal Resolver, the BaseRegistrar, `ensv1_mirror()` and `name_wrapper()` per chain, and Genome's registry, registrar and root on Gnosis. |
| 123–219 | `Namespace` (which name tree a chain resolves) and `refusal()`, the check a host makes before any EVM setup. |
| 221–323 | `EnsError`, the refusal strings, `OffchainLookup`, `Display`. |
| 325–377 | `EnsOwnership`, the `EthCaller` trait, the `ExecutorCaller` adapter. |
| 379–402 | `ResolverInfo`, `resolve_address`. |
| 404–550 | `resolve_ownership`, `v1_decides` (ENSv2), `call_address`, `call_u64`. |
| 552–667 | The other record types: one function each, all over `resolve_record`. |
| 669–793 | Reverse lookup (exact `<hex>.addr.reverse` resolver, else a wildcard resolver higher up), forward verification, the reverse name. |
| 795–827 | Public answer decoders, shared with the CCIP-Read continuation. |
| 829–883 | `resolve_record` (ENSIP-10 wildcard support), `call_wrapped`. |
| 885–955 | CCIP-Read: `ccip_callback`, `revert_outcome`, `decode_offchain_lookup` (≤ 32 URLs). |
| 957–1005 | Registry walk: `find_resolver`, `supports_interface`. |
| 1007–1079 | Tests: the scripted `MockCaller` and ABI helpers. |
| 1080–1222 | Tests: Genome on Gnosis, and chains without a name tree. |
| 1223–1544 | Tests: selectors, the resolver walk, every record type. |
| 1545–1934 | Tests: reverse resolution and CCIP-Read rounds. |
| 1936–2081 | Tests: ownership. |
| 2083–2257 | Tests: ENSv2 (#671). |

#### Which tree, and refusing early

`rust/myotis-evm/src/ens/mod.rs` · lines 150–172

```rust
pub fn for_chain(chain_id: u64) -> Option<Namespace> {
    match chain_id {
        100 => Some(Namespace {
            registry: GENOME_REGISTRY,
            root: GENOME_ROOT,
            registrar_tld: GENOME_TLD,
            registrar: GENOME_REGISTRAR,
            required_tld: Some(GENOME_TLD),
            universal_resolver: None,
        }),
        // Holesky (17000) is retired and not hosted, but stays an ENS chain
        // here as in the Java table, which still pins it.
        1 | 11_155_111 | 17_000 => Some(Namespace {
            registry: REGISTRY,
            root: [0u8; 32],
            registrar_tld: "eth",
            registrar: BASE_REGISTRAR,
            required_tld: None,
            universal_resolver: Some(UNIVERSAL_RESOLVER),
        }),
        _ => None,
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `1 | 11_155_111 | 17_000 =>` is an or-pattern over integers. `Namespace` derives `Copy` (line 126): its fields are byte arrays, `&'static str` and `Option`s of those, all `Copy`, so a whole namespace is copied around like an integer.
- *[Protocol & domain](01-primer.md#primer-domain)* **No tree is a refusal, not a fallback.** Mainnet's registry address holds nothing on another chain, so resolving there would answer a well-formed “no record”. Chiado, for instance, gets `NO_NAME_SERVICE`. On Gnosis only `.gno` names resolve, under Genome's root node; `vitalik.eth` there is refused with `ONLY_GNO_NAMES` rather than hashed into the wrong tree, and reverse lookups are refused too.

`rust/myotis-evm/src/ens/mod.rs` · lines 230–266

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsError {
    /// The name is malformed (empty/oversized label).
    InvalidName(&'static str),
    /// The resolver reverted with ERC-3668 `OffchainLookup`: the record resolves
    /// OFFCHAIN via a CCIP-Read gateway. Carries the decoded 5-tuple (when the
    /// revert body parsed) so the HOST can drive the gateway and re-enter via
    /// the callback (EL-C-5-3 — HTTP stays outside this crate by design).
    /// `wrapped` = the ORIGINAL dispatch went through the ENSIP-10 `resolve()`
    /// wrap, so whichever callback round finally answers must bytes-unwrap its
    /// return; it describes the original call's decode contract, NOT where this
    /// particular revert occurred, and is therefore carried unchanged through
    /// callback rounds. A tuple that fails to parse is `lookup: None` — still
    /// distinguishable from "no record".
    ///
    /// `reverse_claim` names the step of a reverse lookup the revert came from.
    /// `Some(name)`: forward-verifying `name`, the claim the reverse record
    /// already made — the round answers `name`'s ADDRESS record, which the
    /// continuation compares with the queried address
    /// ([`reverse_forward_answer`]). `None`: any other lookup, a reverse one's
    /// claim read included, whose round answers the queried record itself.
    OffchainLookup {
        lookup: Option<Box<OffchainLookup>>,
        wrapped: bool,
        reverse_claim: Option<String>,
    },
    /// A resolution `eth_call` failed for a non-revert reason (state unavailable,
    /// halt, unsupported chain). A plain revert is treated as "no record", not an
    /// error.
    Call(EvmError),
    /// The query is outside what this engine can answer for this chain — a
    /// non-`.gno` name on Gnosis Chain, or a reverse lookup there (Genome keeps
    /// reverse records outside the tree this resolver reads), refused before any
    /// call; or the ownership of a name ENSv2 decides ([`ENSV2_OWNERSHIP`]),
    /// refused once chain state shows it. Never answered as "no record".
    Unsupported(&'static str),
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* “No record” is `Ok(None)`, not an error. An offchain name *is* an error, because answering “no record” for a name that exists offchain would be wrong. `wrapped` remembers whether the original call went through the ENSIP-10 `resolve()` wrapper, and `reverse_claim` (new) remembers that the round is a reverse lookup's forward check, so the host's continuation compares the answer with the queried address.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `lookup: Option<Box<OffchainLookup>>`: the code does not say why the lookup is boxed. A common reason is that an enum is as large as its largest variant, and a `Box` keeps this variant small; the lookup carries vectors and a URL list. `Unsupported(&'static str)` carries one of the constant refusal strings defined right below.

`rust/myotis-evm/src/ens/mod.rs` · lines 349–377

```rust
/// The verified-`eth_call` capability the resolver reads through. Implemented for
/// the real [`EvmExecutor`] via [`ExecutorCaller`]; mocked in tests.
pub trait EthCaller {
    /// A from-less view call to `target` with `calldata`. A revert surfaces as
    /// `Err(EvmError::Reverted { .. })` (the resolver treats that as "no record").
    fn eth_call(&self, target: [u8; 20], calldata: &[u8]) -> Result<Vec<u8>, EvmError>;

    /// The chain the calls run against — selects the name tree
    /// ([`Namespace::for_chain`]). Required, so no caller can silently hash a
    /// Gnosis name into the ENS tree; [`ExecutorCaller`] reports its block's id.
    fn chain_id(&self) -> u64;
}

/// Binds an [`EvmExecutor`] + [`BlockContext`] as an [`EthCaller`] (anonymous
/// zero-sender view calls, which is what ENS registry/resolver reads are).
pub struct ExecutorCaller<'a> {
    pub executor: &'a EvmExecutor,
    pub ctx: &'a BlockContext,
}

impl EthCaller for ExecutorCaller<'_> {
    fn eth_call(&self, target: [u8; 20], calldata: &[u8]) -> Result<Vec<u8>, EvmError> {
        self.executor.call_view(target, calldata, self.ctx)
    }

    fn chain_id(&self) -> u64 {
        self.ctx.chain_id
    }
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes)* `ExecutorCaller<'a>` is just two references, and `'a` stops it from outliving the executor or the context. `ElReader` builds one inside a `move` closure that owns both and runs on a blocking thread.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `EthCaller` has *no* `Send + Sync` bound (it is used as `&dyn EthCaller` on one thread), so the test mock may count calls with a non-thread-safe `RefCell`. Compare `SnapStateOracle`, whose bound rules that out.
- *[Protocol & domain](01-primer.md#primer-domain)* `chain_id()` is a required method with no default. The doc's reason: no caller can then silently hash a Gnosis name into the ENS tree.

#### ENSv2: when v1 no longer speaks for a name

ENSv2 is ENS's new registry design, live on Sepolia during its beta (issue #671). For a name that ENSv2 decides, the v1 registry and BaseRegistrar this file reads no longer speak for its ownership: their entries may be empty (a name registered only in ENSv2) or stale (an expired v1 entry). So `resolve_ownership` first asks ENSv2's Universal Resolver whether v1 still decides the name, and refuses if it does not. The record reads are not gated this way.

`rust/myotis-evm/src/ens/mod.rs` · lines 504–528

```rust
fn v1_decides(
    caller: &dyn EthCaller,
    ur: [u8; 20],
    registry: [u8; 20],
    dns: &[u8],
) -> Result<bool, EnsError> {
    if call_address(caller, ur, &abi::encode_call_no_args("ROOT_REGISTRY()"))?.is_none() {
        return Ok(true);
    }
    let Some(mirror) = ensv1_mirror(caller.chain_id()) else {
        return Ok(false);
    };
    // A revert here means the Universal Resolver could not walk the name; whether
    // v1 decides it is then unknown, which is not a yes.
    let Some(resolver) =
        call_address(caller, ur, &abi::encode_call_bytes("findResolver(bytes)", dns))?
    else {
        return Ok(false);
    };
    if resolver != mirror {
        return Ok(false);
    }
    let mirrored = call_address(caller, resolver, &abi::encode_call_no_args("REGISTRY_V1()"))?;
    Ok(mirrored == Some(registry))
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* Two `let … else` statements in a row. Each binds a value or returns `Ok(false)`: no mirror pinned for this chain, or a Universal Resolver that could not walk the name (“unknown is not a yes”). Note what is *not* folded into “false”: `call_address` maps only a *revert* to `None`; a halt or unavailable state comes back through `?` as `EnsError::Call`, so missing state cannot turn into “v1 decides”.
- *[Protocol & domain](01-primer.md#primer-domain)* **Pinned, not recognised.** The mirror must be the pinned address *and* its `REGISTRY_V1()` must name this registry. A name's ENSv2 owner sets its resolver and could deploy one that answers `REGISTRY_V1()` correctly; trusting the getter alone would let any owner make an ENSv2 name read as unowned (the #672 review). Where ENSv2 is live but no mirror is pinned (mainnet right after activation), every ownership read is refused.

#### Reverse resolution and CCIP-Read

`reverse_resolve` reads the claimed primary name from the resolver of the exact `<hex>.addr.reverse` node, calling `name(bytes32)` directly with no `supportsInterface` probe: old reverse resolvers predate ERC-165 and halt on the probe. Only an address without its own reverse resolver walks up to a wildcard resolver on `addr.reverse` or `reverse` (new, #671), which is how ENSv2 primary names on Sepolia answer. Either way the claim is then checked forward.

`rust/myotis-evm/src/ens/mod.rs` · lines 761–774

```rust
pub fn verify_reverse_claim(
    caller: &dyn EthCaller,
    address: [u8; 20],
    claimed: String,
) -> Result<Option<String>, EnsError> {
    match resolve_address(caller, &claimed) {
        Ok(Some(fwd)) if fwd == address => Ok(Some(claimed)),
        Ok(_) | Err(EnsError::InvalidName(_)) => Ok(None),
        Err(EnsError::OffchainLookup { lookup, wrapped, .. }) => {
            Err(EnsError::OffchainLookup { lookup, wrapped, reverse_claim: Some(claimed) })
        }
        Err(e) => Err(e),
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Ownership & moves](01-primer.md#primer-ownership)* The `match` works on the *owned* result of `resolve_address`, so its patterns can move values out. `Ok(Some(fwd)) if fwd == address` is a guarded arm. `Ok(_) | Err(EnsError::InvalidName(_))` folds a mismatch and a malformed claim into “no verified name”, so a malicious reverse record cannot force an error. The `OffchainLookup` arm moves `lookup` (the `Box`) and `wrapped` out of the old error into a new one that also carries the claim.
- *[Ownership & moves](01-primer.md#primer-ownership)* `claimed: String` is taken by value. The first arm moves it into `Some(claimed)`, the third into `reverse_claim`; only one arm runs, so the compiler accepts both moves.

> [!NOTE]
> **CCIP-Read, end to end**
>
> The resolver reverts with `OffchainLookup`. `revert_outcome` (lines 925–935) checks the 4-byte selector after a length check, so `data[..4]` cannot panic, and decodes the tuple; any other revert is “no record”. `ElReader` reports an “offchain” outcome. The JVM host's `CcipDriver` (in `myotis-engine-rust`) performs the gateway request and calls back with `method:"ccipCallback"`. `ccip_callback` then runs the verified `sender.callbackFunction(response, extraData)` call and unwraps the result only if `wrapped`. A second `OffchainLookup` keeps the original `wrapped` flag, and the host enforces the recursion cap.

#### The test mock

`rust/myotis-evm/src/ens/mod.rs` · lines 1014–1036

```rust
struct MockCaller {
    #[allow(clippy::type_complexity)]
    handlers: Vec<Box<dyn Fn([u8; 20], &[u8]) -> Option<Result<Vec<u8>, EvmError>>>>,
    calls: RefCell<usize>,
    chain: u64,
}

impl MockCaller {
    fn new() -> MockCaller {
        MockCaller { handlers: Vec::new(), calls: RefCell::new(0), chain: 1 }
    }
    fn on_chain(mut self, chain: u64) -> Self {
        self.chain = chain;
        self
    }
    fn on(
        mut self,
        f: impl Fn([u8; 20], &[u8]) -> Option<Result<Vec<u8>, EvmError>> + 'static,
    ) -> Self {
        self.handlers.push(Box::new(f));
        self
    }
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Lifetimes](01-primer.md#primer-lifetimes)* Every closure has its own anonymous type, so a `Vec` of closures needs `Box<dyn Fn …>`. `on(mut self, f: impl Fn(…) + 'static) -> Self` is a consuming, chainable builder, and `'static` forbids the closure from borrowing short-lived locals, since it will be stored.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Ownership & moves](01-primer.md#primer-ownership)* The tests' handlers are `move` closures. Because the field type is `Fn` (callable many times through `&self`), a handler may not give away what it captured. A handler that returns a captured `Vec` therefore writes `.then(|| Ok(claimed.clone()))`: the inner closure borrows `claimed` from the outer one and returns a fresh copy each time.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `calls: RefCell<usize>` counts calls inside `eth_call(&self, …)` with `*self.calls.borrow_mut() += 1`. Tests assert the count to prove, for example, that a subname's ownership asked only three questions.

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-evm-q1"></a>

**Q1** · Multiple choice

What would break if `SnapStateOracle` were declared without `: Send + Sync`?

- **A.** Nothing; the bounds are documentation
- **B.** revm would reject the database
- **C.** `Arc<dyn SnapStateOracle>` would not be `Send`, so an executor holding it could not be moved to a blocking thread or shared across threads
- **D.** The oracle could no longer return `Result`

[Answer →](answers.md#a-evm-q1)

<a id="q-evm-q2"></a>

**Q2** · Multiple choice

`InMemoryStateProofCache::get_account` returns `…get(&key).cloned()` rather than a reference into the map. Why?

- **A.** The map is only reachable through a `MutexGuard` that dies at the end of the statement; a reference into the map cannot outlive that guard
- **B.** Clones are faster than references
- **C.** `HashMap::get` always returns an owned value
- **D.** To allow the caller to mutate the cache

[Answer →](answers.md#a-evm-q2)

<a id="q-evm-q3"></a>

**Q3** · Written answer

In `OracleDatabase::account`, the sentinel check sits in its own `{ … }` block before the network fetch. What does the block do, and what could go wrong without it?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-evm-q3)

<a id="q-evm-q4"></a>

**Q4** · Multiple choice

Why does `OracleDatabase` implement revm's `DatabaseRef` (`&self`) rather than `Database` (`&mut self`)?

- **A.** `Database` is deprecated
- **B.** Because `&mut` is slower
- **C.** Because revm requires `Send`
- **D.** So the executor can keep ownership of one database and lend it to every loop iteration and every gas-search probe; the price is interior mutability inside

[Answer →](answers.md#a-evm-q4)

<a id="q-evm-q5"></a>

**Q5** · Multiple choice

In `converge_runs`, `self.prefetch_wave(ctx, &fresh, …);` is followed by `seen.merge(fresh);`. What happens if you swap the two lines?

- **A.** It still compiles; order does not matter
- **B.** Compile error: `merge` takes `fresh` by value (moves it), so the later `&fresh` uses a moved value
- **C.** Runtime panic
- **D.** The wave fetches nothing

[Answer →](answers.md#a-evm-q5)

<a id="q-evm-q6"></a>

**Q6** · Written answer

Explain how the prefetch convergence loop decides when to stop, and why an answer can never come from a placeholder.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-evm-q6)

<a id="q-evm-q7"></a>

**Q7** · Multiple choice

`RequestInspector` records needed code into a `&RefCell<HashSet<…>>`, while `OracleDatabase` keeps its access set in a `Mutex`. Why the difference?

- **A.** `RefCell` is faster, and the database author did not know about it
- **B.** The database's type must be `Sync` (it is reached through a shared reference that the type system lets cross threads), and a `RefCell` is never `Sync`; the inspector's set is a local of one run on one thread, where a run-time borrow check is enough
- **C.** A `Mutex` cannot hold a `HashSet`
- **D.** revm forbids `Mutex` inside inspectors

[Answer →](answers.md#a-evm-q7)

<a id="q-evm-q8"></a>

**Q8** · Multiple choice

During a discovery pass, `block_hash_ref` reads the EIP-2935 history slot for block k and gets zero, and the miss counter has moved. What does it do?

- **A.** Returns zero as the block hash, because a written slot is never zero
- **B.** Walks the header chain at once
- **C.** Returns zero as a placeholder: the slot is in the access set, the next wave fetches it, and the real run reads the true value
- **D.** Returns `BlockHashUnsupported`

[Answer →](answers.md#a-evm-q8)

<a id="q-evm-q9"></a>

**Q9** · Multiple choice

`read_index` checks `v <= MAX_INDEX as u64` *before* `v as usize`. Why does the order matter?

- **A.** On 32-bit targets `as usize` truncates silently (232 → 0), which would bypass the guard
- **B.** It does not
- **C.** `as usize` panics on overflow
- **D.** Because `u64` comparisons are faster

[Answer →](answers.md#a-evm-q9)

<a id="q-evm-q10"></a>

**Q10** · Multiple choice

Why is an ERC-3668 `OffchainLookup` revert reported as `Err(EnsError::OffchainLookup{…})` instead of `Ok(None)`?

- **A.** Because all reverts are errors
- **B.** Because the tuple cannot be decoded
- **C.** To make tests easier
- **D.** The record exists, just offchain. “No record” would be a well-formed but wrong answer, so the host must be told to perform the gateway round

[Answer →](answers.md#a-evm-q10)

<a id="q-evm-q11"></a>

**Q11** · Multiple choice

`EvmError::FailedWithGas` holds `error: Box<EvmError>`. What would happen with `error: EvmError` instead?

- **A.** It would compile but use more stack
- **B.** Compile error: a recursive type has infinite size, because an enum is as large as its largest variant and this variant would contain the whole enum
- **C.** It would compile, and `Clone` would become a deep copy
- **D.** The `Display` impl would recurse forever

[Answer →](answers.md#a-evm-q11)

<a id="q-evm-q12"></a>

**Q12** · Written answer

`with_sender_nonce(mut overrides: StateOverrides, tx: &TxRequest) -> Result<StateOverrides, EvmError>` starts its edit with `let mut entry = overrides.get(&tx.from).cloned().unwrap_or_default();`. Explain the ownership of `overrides` through this function, and why the `.cloned()` is needed.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-evm-q12)

<a id="q-evm-q13"></a>

**Q13** · Written answer

`v1_decides` decides whether ENS v1 still speaks for a name. Why does `resolve_ownership` refuse instead of answering from v1 when it is unsure, and why is the v1 mirror pinned by address rather than recognised by its `REGISTRY_V1()` getter?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-evm-q13)

<a id="q-evm-q14"></a>

**Q14** · Written answer

`MockCaller` stores handlers as `Vec<Box<dyn Fn([u8; 20], &[u8]) -> Option<Result<Vec<u8>, EvmError>>>>`, added with `on(mut self, f: impl Fn(…) + 'static) -> Self`. A test handler that returns a captured byte vector is written `move |t, cd| (…).then(|| Ok(claimed.clone()))`. Explain the `Box<dyn …>`, the `'static`, and the `.clone()`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-evm-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
