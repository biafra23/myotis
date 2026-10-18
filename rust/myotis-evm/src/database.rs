//! [`OracleDatabase`]: the `revm` [`DatabaseRef`] adapter over a
//! [`SnapStateOracle`] and the caches.
//!
//! One instance is bound to ONE block's anchored `state_root` — build a fresh
//! one per `eth_call`. Reads resolve in three tiers, cheapest first:
//!
//! 1. the per-call **view cache** (private here) — dedups repeated reads within
//!    this one call;
//! 2. the cross-call [`StateProofCache`] — a `stateRoot`-keyed verified fact from
//!    an earlier call (this is what makes a MetaMask number-pinned retry cheap);
//! 3. the [`SnapStateOracle`] — a fresh, verified network fetch, whose result is
//!    promoted into both caches.
//!
//! To drive the EVM, wrap it: `WrapDatabaseRef(oracle_database)` implements
//! `revm::Database`.
//!
//! ## `BLOCKHASH`
//!
//! The call runs on block N's post-state with N's header as the block
//! context, so `BLOCKHASH(k)` is defined for `N-256 <= k < N` and zero
//! otherwise (revm enforces that window before it asks
//! [`DatabaseRef::block_hash_ref`]; the adapter answers zero outside it too).
//! Inside it, every hash comes from what the call already proves
//! ([`BlockHashes`]):
//!
//! 1. `k = N-1`: N's `parentHash`, from the verified header.
//! 2. otherwise, from Prague on: the EIP-2935 history contract's storage at
//!    slot `k % 8191`, read through the same verified tiers as any `SLOAD`
//!    (proven against the call's state root, prefetched in waves, cached by
//!    root). N's post-state holds there the hash of every block from the
//!    fork's parent up to N-1, and a slot it never wrote holds zero, which no
//!    block hash is — so a zero means "not in the contract" and falls through.
//! 3. what the contract does not hold (before Prague, or a block older than
//!    the fork's parent): a header walk down from N-1, proven by
//!    [`SnapStateOracle::fetch_block_hash`].
//!
//! A caller's state override never reaches it: `BLOCKHASH` reads the chain,
//! not the call's hypothetical state (geth answers it from its headers).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, Bytes, B256, U256};
use revm::state::{AccountInfo, Bytecode};

use myotis_core::keccak::keccak256;
use myotis_core::trie::EMPTY_CODE_HASH;

use crate::block::BlockContext;
use crate::cache::{BytecodeCache, StateProofCache};
use crate::oracle::{OracleAccount, OracleError, SnapStateOracle};
use crate::overrides::StateOverrides;

/// The EIP-2935 history contract (`HISTORY_STORAGE_ADDRESS`): the same
/// address on every chain this engine serves.
pub const HISTORY_STORAGE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0xF9, 0x08, 0x27, 0xF1, 0xC5, 0x3a, 0x10, 0xcb, 0x7A, 0x02, 0x33, 0x5B, 0x17, 0x53, 0x20, 0x00,
    0x29, 0x35,
];

/// The history contract's ring size (`HISTORY_SERVE_WINDOW`): block `k`'s
/// hash lives at slot `k % 8191`.
pub const HISTORY_SERVE_WINDOW: u64 = 8191;

/// How far back `BLOCKHASH` reaches (the opcode's own window).
const BLOCKHASH_WINDOW: u64 = 256;

/// What `BLOCKHASH` answers from for one call (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHashes {
    /// The call's block N (the NUMBER opcode's value).
    pub number: u64,
    /// N's verified `parentHash`; `None` refuses `BLOCKHASH(N-1)` and every
    /// header walk (see [`BlockContext::parent_hash`]).
    pub parent_hash: Option<[u8; 32]>,
    /// Whether the call's spec is Prague or later, i.e. whether N's
    /// post-state can hold the EIP-2935 history contract's ring.
    pub history_contract: bool,
}

impl BlockHashes {
    /// The source for a call in `ctx` under a spec where the history contract
    /// is (`history_contract`) or is not active.
    pub fn for_context(ctx: &BlockContext, history_contract: bool) -> BlockHashes {
        BlockHashes { number: ctx.block_number, parent_hash: ctx.parent_hash, history_contract }
    }
}

/// The per-call cache (tier 1). Bound to one `OracleDatabase` (one call) and
/// discarded with it — it holds this call's reads regardless of proof/root and
/// so is NEVER shared across calls (unlike the cross-call [`StateProofCache`]).
///
/// Note: the Java engine also has a per-*resolution* "in-flight dedup" tier that
/// collapses concurrent async account fetches into one future. That tier only
/// exists to dedup *parallelism*; a single synchronous `transact` reads serially,
/// so the view cache already dedups every repeat. True in-flight dedup arrives
/// with the async prefetch layer (a later Milestone-C slice).
#[derive(Default)]
struct ViewCache {
    /// `None` marks an address proven absent — cached so we don't re-fetch it.
    accounts: HashMap<[u8; 20], Option<OracleAccount>>,
    storage: HashMap<([u8; 20], U256), U256>,
    /// Per-call bytecode (the Java `SyncStateView` holds code too): keeps the
    /// primed/fetched code alive across the convergence loop's iterations even
    /// when the shared bytecode cache is a Noop — a sentinel pass must execute
    /// the REAL primed code, not an empty placeholder.
    code: HashMap<[u8; 32], Bytes>,
    /// Block hashes a header walk proved for this call
    /// ([`SnapStateOracle::fetch_block_hash`]).
    block_hashes: HashMap<u64, [u8; 32]>,
}

/// Everything one execution TOUCHED (hit or miss) — the prefetch loop diffs
/// consecutive snapshots to find newly-discovered dependencies (the Java
/// `AccessTracker` twin, collapsed to the DB layer: every revm read passes
/// through here, so no separate opcode tracer is needed).
/// Growth is gas-bounded, not attacker-controlled: cold reads cost revm gas
/// regardless of what this DB returns (sentinel zeros included), so one 30 M
/// run tops out around ~14k distinct slots / ~11k accounts; `seen` accumulates
/// ≤12 largely-overlapping iterations (`PREFETCH_ITERATION_CAP`) and dies
/// with the per-call database.
#[derive(Debug, Default, Clone)]
pub struct AccessSet {
    pub accounts: std::collections::HashSet<[u8; 20]>,
    pub slots: std::collections::HashSet<([u8; 20], U256)>,
    pub code_hashes: std::collections::HashSet<[u8; 32]>,
}

impl AccessSet {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.slots.is_empty() && self.code_hashes.is_empty()
    }

    /// The entries of `self` not present in `seen`.
    pub fn minus(&self, seen: &AccessSet) -> AccessSet {
        AccessSet {
            accounts: self.accounts.difference(&seen.accounts).copied().collect(),
            slots: self.slots.difference(&seen.slots).copied().collect(),
            code_hashes: self.code_hashes.difference(&seen.code_hashes).copied().collect(),
        }
    }

    pub fn merge(&mut self, other: AccessSet) {
        self.accounts.extend(other.accounts);
        self.slots.extend(other.slots);
        self.code_hashes.extend(other.code_hashes);
    }
}

/// Sentinel-mode + access-tracking state (the Java `SyncStateView` sentinel
/// semantics): with sentinel ON, a read that would need the network (tier 3)
/// instead returns a zero-shaped placeholder WITHOUT caching it and bumps the
/// miss counter — one cheap discovery pass per data-dependency hop.
#[derive(Default)]
struct Track {
    sentinel: bool,
    misses: u64,
    set: AccessSet,
}

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

impl OracleDatabase {
    /// A database for `state_root`, sharing the cross-call `proof_cache` and
    /// `bytecode_cache` across every call the host makes.
    pub fn new(
        oracle: Arc<dyn SnapStateOracle>,
        state_root: [u8; 32],
        proof_cache: Arc<dyn StateProofCache>,
        bytecode_cache: Arc<dyn BytecodeCache>,
    ) -> OracleDatabase {
        OracleDatabase::with_overrides(
            oracle,
            state_root,
            proof_cache,
            bytecode_cache,
            StateOverrides::new(),
        )
    }

    /// As [`Self::new`], with caller-supplied [`StateOverrides`] layered over
    /// the verified state for this call.
    pub fn with_overrides(
        oracle: Arc<dyn SnapStateOracle>,
        state_root: [u8; 32],
        proof_cache: Arc<dyn StateProofCache>,
        bytecode_cache: Arc<dyn BytecodeCache>,
        overrides: StateOverrides,
    ) -> OracleDatabase {
        OracleDatabase {
            oracle,
            state_root,
            proof_cache,
            bytecode_cache,
            view: Mutex::new(ViewCache::default()),
            track: Mutex::new(Track::default()),
            overrides,
            block_hashes: None,
        }
    }

    /// Serve `BLOCKHASH` from `source` (see the module docs). Without it the
    /// database refuses the opcode.
    pub fn with_block_hashes(mut self, source: BlockHashes) -> OracleDatabase {
        self.block_hashes = Some(source);
        self
    }

    /// Toggle sentinel mode (prefetch discovery passes). OFF by default.
    pub fn set_sentinel(&self, on: bool) {
        self.track.lock().unwrap().sentinel = on;
    }

    /// Cumulative count of sentinel placeholders handed out — if a run finishes
    /// with this unchanged, every read was a verified hit and the run is
    /// byte-identical to a real one (the hit-only fast path).
    pub fn sentinel_misses(&self) -> u64 {
        self.track.lock().unwrap().misses
    }

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
}

/// Build a revm [`Bytecode`] from verified raw code WITHOUT panicking.
///
/// `Bytecode::new_raw` is not panic-free — it `.expect()`s inside, and any blob
/// beginning `0xEF01` (the EIP-7702 magic) that is not a well-formed 23-byte
/// delegation makes it panic → `abort` under the workspace's release
/// `panic = "abort"`. Such code is legal on-chain (e.g. pre-London `0xEF`-leading
/// legacy code), so it must not crash the engine. `new_raw_checked` returns the
/// correct `Eip7702` variant for a valid delegation and `Legacy` for everything
/// else; on the rare malformed-`0xEF01` error we fall back to `new_legacy`, which
/// loads the real verified bytes as legacy code (it reverts on the invalid `0xEF`
/// opcode at run time — exactly what a full node does) and never panics.
fn to_bytecode(bytes: Bytes) -> Bytecode {
    Bytecode::new_raw_checked(bytes.clone()).unwrap_or_else(|_| Bytecode::new_legacy(bytes))
}

fn to_account_info(acc: &OracleAccount) -> AccountInfo {
    AccountInfo {
        balance: acc.balance,
        nonce: acc.nonce,
        code_hash: B256::from(acc.code_hash),
        // Left None: revm loads the code lazily via `code_by_hash_ref` only when
        // the account is actually executed, so a balance/nonce read never pulls
        // bytecode.
        code: None,
        ..AccountInfo::default()
    }
}

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

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let hash: [u8; 32] = code_hash.0;
        // An overridden account's code is addressed by ITS keccak, so answer
        // from the override before any cache or fetch — and never store it.
        if let Some(code) = self.overrides.code_by_hash(&hash) {
            return Ok(to_bytecode(code.to_vec().into()));
        }
        // Empty-code hash → provably empty code, no fetch.
        if hash == EMPTY_CODE_HASH {
            return Ok(Bytecode::default());
        }
        self.track.lock().unwrap().set.code_hashes.insert(hash);
        // Tier 1 — this call's view (primed target code lives here).
        if let Some(bytes) = self.view.lock().unwrap().code.get(&hash) {
            return Ok(to_bytecode(bytes.clone()));
        }
        // A cache hit was verified (below) when first stored, and the cache is
        // keyed by hash, so it needs no re-check.
        if let Some(bytes) = self.bytecode_cache.get(&hash) {
            self.view.lock().unwrap().code.insert(hash, bytes.clone());
            return Ok(to_bytecode(bytes));
        }
        // Sentinel: empty code, uncached, counted — nested CALLs short-circuit
        // in discovery passes (expected; the real pass executes them).
        {
            let mut track = self.track.lock().unwrap();
            if track.sentinel {
                track.misses += 1;
                return Ok(Bytecode::default());
            }
        }
        let bytes: Bytes = self.oracle.fetch_bytecode(&hash)?.into();
        // Defense-in-depth at the trust boundary: bytecode is content-addressed,
        // so re-verify keccak(code) == hash here even though the oracle already
        // checked it. Fail closed on any mismatch — never execute unverified code.
        let got = keccak256(&bytes);
        if got != hash {
            return Err(OracleError::InvalidProof {
                // Carry the call's state root for telemetry; address is left zero
                // because bytecode is content-addressed (keyed by code hash, not by
                // an account) — the detail says so rather than implying an account.
                state_root: self.state_root,
                address: [0u8; 20],
                detail: format!(
                    "bytecode hash mismatch (content-addressed, no account context): \
                     expected {}, got {}",
                    B256::from(hash),
                    B256::from(got)
                ),
            });
        }
        self.bytecode_cache.put(&hash, bytes.clone());
        self.view.lock().unwrap().code.insert(hash, bytes.clone());
        Ok(to_bytecode(bytes))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        // An override may answer authoritatively (a `state` replacement makes
        // even an unlisted slot provably zero FOR THIS CALL); `None` means the
        // caller said nothing about this slot, so verified state answers.
        if let Some(v) = self.overrides.get(&address.into_array()).and_then(|o| o.storage(index)) {
            return Ok(v);
        }
        self.verified_storage(address.into_array(), index)
    }

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
}

impl OracleDatabase {
    /// A storage slot from verified state, through the three tiers — never an
    /// override (the caller of `storage_ref` applies those first).
    fn verified_storage(&self, addr: [u8; 20], index: U256) -> Result<U256, OracleError> {
        self.track.lock().unwrap().set.slots.insert((addr, index));
        // Tier 1.
        if let Some(v) = self.view.lock().unwrap().storage.get(&(addr, index)) {
            return Ok(*v);
        }
        // Tier 2.
        if let Some(v) = self
            .proof_cache
            .get_storage(&self.state_root, &addr, &index)
        {
            self.view.lock().unwrap().storage.insert((addr, index), v);
            return Ok(v);
        }
        // Sentinel: placeholder zero, uncached, counted (see `account`).
        {
            let mut track = self.track.lock().unwrap();
            if track.sentinel {
                track.misses += 1;
                return Ok(U256::ZERO);
            }
        }
        // Tier 3 — verified fetch (the oracle handles the account/storage-root and
        // empty-trie short-circuit internally). Lock released across it as above.
        let value = self.oracle.fetch_storage(&self.state_root, addr, index)?;
        self.proof_cache
            .put_storage(&self.state_root, &addr, &index, value);
        self.view
            .lock()
            .unwrap()
            .storage
            .insert((addr, index), value);
        Ok(value)
    }

    /// Block `number`'s hash from a header walk down from the verified block
    /// `anchor_number` (hash `anchor_hash`): this call's view first, else the
    /// oracle's proven walk.
    ///
    /// A discovery pass walks too, rather than handing out a placeholder: a
    /// walk is one request no prefetch wave could batch, so deferring it to
    /// the real run saves nothing, while a zero hash would cost every pass the
    /// hit-only fast path and could steer discovery down a wrong branch.
    fn walked_block_hash(&self, anchor_number: u64, anchor_hash: &[u8; 32], number: u64) -> Result<[u8; 32], OracleError> {
        if let Some(hash) = self.view.lock().unwrap().block_hashes.get(&number) {
            return Ok(*hash);
        }
        let hash = self.oracle.fetch_block_hash(anchor_number, anchor_hash, number)?;
        self.view.lock().unwrap().block_hashes.insert(number, hash);
        Ok(hash)
    }
}
