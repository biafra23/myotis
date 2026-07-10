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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use revm::database_interface::DatabaseRef;
use revm::primitives::{Address, Bytes, B256, U256};
use revm::state::{AccountInfo, Bytecode};

use myotis_core::keccak::keccak256;
use myotis_core::trie::EMPTY_CODE_HASH;

use crate::cache::{BytecodeCache, StateProofCache};
use crate::oracle::{OracleAccount, OracleError, SnapStateOracle};

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
}

/// Everything one execution TOUCHED (hit or miss) — the prefetch loop diffs
/// consecutive snapshots to find newly-discovered dependencies (the Java
/// `AccessTracker` twin, collapsed to the DB layer: every revm read passes
/// through here, so no separate opcode tracer is needed).
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
        OracleDatabase {
            oracle,
            state_root,
            proof_cache,
            bytecode_cache,
            view: Mutex::new(ViewCache::default()),
            track: Mutex::new(Track::default()),
        }
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

    /// The state root this database is pinned to.
    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
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
        Ok(self
            .account(address.into_array())?
            .as_ref()
            .map(to_account_info))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let hash: [u8; 32] = code_hash.0;
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
        let addr = address.into_array();
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

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // No local block store to serve historical hashes; a contract reading
        // BLOCKHASH cannot be executed. Fail fast (matches the Java engine).
        Err(OracleError::BlockHashUnsupported { number })
    }
}
