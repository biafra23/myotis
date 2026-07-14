//! The EVM state caches.
//!
//! Two of the three cache tiers the Java `myotis-evm` uses live here (the third,
//! the per-call view cache, is private to [`crate::database::OracleDatabase`]
//! because it is bound to one `eth_call` run):
//!
//! * [`StateProofCache`] — the CROSS-CALL cache, keyed by `stateRoot`. An entry
//!   is stored only *after* its MPT proof verified against that root, and state
//!   at a fixed `stateRoot` is immutable — so a cached `(stateRoot, address[,
//!   slot]) → value` is a cryptographic fact, not peer-trusted data. Reusing it
//!   across any call pinned to that same root is sound, which is what lets a
//!   MetaMask number-pinned retry (the identical call, over and over) converge
//!   instead of re-fetching hundreds of proofs each time.
//! * [`BytecodeCache`] — code is content-addressed (`keccak256(code) == codeHash`)
//!   and therefore immutable forever, so this cache never evicts and is safe to
//!   share across calls and (later) persist across sessions.
//!
//! Both are traits (SPIs) so a wallet host can later swap the in-memory backend
//! for a persistent one without touching the EVM. The defaults are a no-op
//! (correct, just cold) and a bounded in-memory LRU.

use std::collections::HashMap;
use std::sync::Mutex;

use revm::primitives::{Bytes, U256};

use crate::oracle::OracleAccount;

/// Cross-call, `stateRoot`-keyed cache of proof-verified account and storage
/// facts. Every getter/putter takes the `stateRoot` the fact was proven against;
/// implementations MUST NOT return a value cached under a different root.
///
/// `get_account` returns `Option<Option<OracleAccount>>` so the two "absents" stay
/// distinct: the OUTER `None` is a cache miss, while `Some(None)` is the cached,
/// proof-verified fact that the account is ABSENT at this root. Absent-account
/// reads are common in EVM execution (any never-touched address), so caching the
/// exclusion proof — like storage caches a zero slot — keeps a repeated call from
/// going cold to the oracle each time.
pub trait StateProofCache: Send + Sync {
    fn get_account(
        &self,
        state_root: &[u8; 32],
        address: &[u8; 20],
    ) -> Option<Option<OracleAccount>>;
    fn put_account(
        &self,
        state_root: &[u8; 32],
        address: &[u8; 20],
        account: Option<OracleAccount>,
    );
    fn get_storage(&self, state_root: &[u8; 32], address: &[u8; 20], slot: &U256) -> Option<U256>;
    fn put_storage(&self, state_root: &[u8; 32], address: &[u8; 20], slot: &U256, value: U256);
}

/// The default: caches nothing (every read goes to the oracle). Correct, cold —
/// used until a host installs [`InMemoryStateProofCache`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStateProofCache;

impl StateProofCache for NoopStateProofCache {
    fn get_account(&self, _root: &[u8; 32], _addr: &[u8; 20]) -> Option<Option<OracleAccount>> {
        None
    }
    fn put_account(&self, _root: &[u8; 32], _addr: &[u8; 20], _account: Option<OracleAccount>) {}
    fn get_storage(&self, _root: &[u8; 32], _addr: &[u8; 20], _slot: &U256) -> Option<U256> {
        None
    }
    fn put_storage(&self, _root: &[u8; 32], _addr: &[u8; 20], _slot: &U256, _value: U256) {}
}

type AccountKey = ([u8; 32], [u8; 20]);
type StorageKey = ([u8; 32], [u8; 20], U256);

/// A bounded, in-memory [`StateProofCache`]. Accounts and storage slots are
/// bounded independently at `max_per_kind` entries, each evicting least-recently
/// used. Thread-safe via a `Mutex` per kind (contention is trivial next to a
/// network proof fetch). The account value is `Option<OracleAccount>` so a
/// proof-verified ABSENCE (`None`) is cached too.
pub struct InMemoryStateProofCache {
    accounts: Mutex<Lru<AccountKey, Option<OracleAccount>>>,
    storage: Mutex<Lru<StorageKey, U256>>,
}

impl InMemoryStateProofCache {
    /// `max_per_kind` bounds the account cache and the storage cache separately
    /// (mirrors the Java `StateProofCache.inMemory(maxEntriesPerKind)`).
    pub fn new(max_per_kind: usize) -> InMemoryStateProofCache {
        InMemoryStateProofCache {
            accounts: Mutex::new(Lru::new(max_per_kind)),
            storage: Mutex::new(Lru::new(max_per_kind)),
        }
    }
}

impl StateProofCache for InMemoryStateProofCache {
    fn get_account(&self, root: &[u8; 32], addr: &[u8; 20]) -> Option<Option<OracleAccount>> {
        self.accounts.lock().unwrap().get(&(*root, *addr)).cloned()
    }
    fn put_account(&self, root: &[u8; 32], addr: &[u8; 20], account: Option<OracleAccount>) {
        self.accounts.lock().unwrap().put((*root, *addr), account);
    }
    fn get_storage(&self, root: &[u8; 32], addr: &[u8; 20], slot: &U256) -> Option<U256> {
        self.storage
            .lock()
            .unwrap()
            .get(&(*root, *addr, *slot))
            .copied()
    }
    fn put_storage(&self, root: &[u8; 32], addr: &[u8; 20], slot: &U256, value: U256) {
        self.storage
            .lock()
            .unwrap()
            .put((*root, *addr, *slot), value);
    }
}

/// Content-addressed bytecode cache: `codeHash → code`. Immutable forever, so no
/// eviction and safe to share across calls (and sessions, once persisted).
pub trait BytecodeCache: Send + Sync {
    fn get(&self, code_hash: &[u8; 32]) -> Option<Bytes>;
    fn put(&self, code_hash: &[u8; 32], code: Bytes);
}

/// The default: caches nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBytecodeCache;

impl BytecodeCache for NoopBytecodeCache {
    fn get(&self, _code_hash: &[u8; 32]) -> Option<Bytes> {
        None
    }
    fn put(&self, _code_hash: &[u8; 32], _code: Bytes) {}
}

/// Unbounded in-memory bytecode cache (content-addressed → never evicts).
#[derive(Default)]
pub struct InMemoryBytecodeCache {
    map: Mutex<HashMap<[u8; 32], Bytes>>,
}

impl InMemoryBytecodeCache {
    pub fn new() -> InMemoryBytecodeCache {
        InMemoryBytecodeCache::default()
    }
}

impl BytecodeCache for InMemoryBytecodeCache {
    fn get(&self, code_hash: &[u8; 32]) -> Option<Bytes> {
        self.map.lock().unwrap().get(code_hash).cloned()
    }
    fn put(&self, code_hash: &[u8; 32], code: Bytes) {
        // Content-addressed: first writer wins; a re-put is the identical blob.
        self.map.lock().unwrap().entry(*code_hash).or_insert(code);
    }
}

/// A tiny least-recently-used map: O(1) `get`/`put`, O(n) eviction scan only when
/// a new key overflows `cap` (n is the cap, negligible beside the network fetch
/// an eviction stands in for). Recency is a monotonically increasing tick, not a
/// wall clock — safe in the sans-I/O crate. `cap == 0` disables caching.
///
/// Public: shared by the proof/bytecode caches here and by consumers with the
/// same bounded-map need (the EL reader's verified block-hash → number map —
/// the Java `blockHashToNumber` twin), so the eviction subtleties live once.
pub struct Lru<K, V> {
    cap: usize,
    tick: u64,
    map: HashMap<K, (V, u64)>,
}

impl<K: std::hash::Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(cap: usize) -> Lru<K, V> {
        Lru {
            cap,
            tick: 0,
            map: HashMap::new(),
        }
    }

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

#[cfg(test)]
mod tests {
    use super::Lru;

    #[test]
    fn lru_caps_and_prefers_recently_used() {
        let mut lru: Lru<u64, u64> = Lru::new(4);
        for n in 0..4 {
            lru.put(n, n * 10);
        }
        // Touch entry 0 so it is the most recently used, then overflow by one:
        // the eviction must take the LEAST recently used (entry 1), not 0.
        assert_eq!(lru.get(&0), Some(&0));
        lru.put(99, 990);
        assert_eq!(lru.map.len(), 4);
        assert_eq!(lru.get(&0), Some(&0), "recently-used entry survives");
        assert_eq!(lru.get(&1), None, "least-recently-used entry evicted");
        assert_eq!(lru.get(&99), Some(&990));
        // Re-inserting an existing key updates in place (no growth, no evict).
        lru.put(0, 42);
        assert_eq!(lru.get(&0), Some(&42));
        assert_eq!(lru.map.len(), 4);
        // cap == 0 disables caching entirely.
        let mut off: Lru<u64, u64> = Lru::new(0);
        off.put(1, 1);
        assert_eq!(off.get(&1), None);
    }
}
