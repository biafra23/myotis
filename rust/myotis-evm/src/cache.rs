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
pub trait StateProofCache: Send + Sync {
    fn get_account(&self, state_root: &[u8; 32], address: &[u8; 20]) -> Option<OracleAccount>;
    fn put_account(&self, state_root: &[u8; 32], address: &[u8; 20], account: &OracleAccount);
    fn get_storage(&self, state_root: &[u8; 32], address: &[u8; 20], slot: &U256) -> Option<U256>;
    fn put_storage(&self, state_root: &[u8; 32], address: &[u8; 20], slot: &U256, value: U256);
}

/// The default: caches nothing (every read goes to the oracle). Correct, cold —
/// used until a host installs [`InMemoryStateProofCache`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStateProofCache;

impl StateProofCache for NoopStateProofCache {
    fn get_account(&self, _root: &[u8; 32], _addr: &[u8; 20]) -> Option<OracleAccount> {
        None
    }
    fn put_account(&self, _root: &[u8; 32], _addr: &[u8; 20], _account: &OracleAccount) {}
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
/// network proof fetch).
pub struct InMemoryStateProofCache {
    accounts: Mutex<Lru<AccountKey, OracleAccount>>,
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
    fn get_account(&self, root: &[u8; 32], addr: &[u8; 20]) -> Option<OracleAccount> {
        self.accounts.lock().unwrap().get(&(*root, *addr)).cloned()
    }
    fn put_account(&self, root: &[u8; 32], addr: &[u8; 20], account: &OracleAccount) {
        self.accounts
            .lock()
            .unwrap()
            .put((*root, *addr), account.clone());
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
struct Lru<K, V> {
    cap: usize,
    tick: u64,
    map: HashMap<K, (V, u64)>,
}

impl<K: std::hash::Hash + Eq + Clone, V> Lru<K, V> {
    fn new(cap: usize) -> Lru<K, V> {
        Lru {
            cap,
            tick: 0,
            map: HashMap::new(),
        }
    }

    fn get(&mut self, key: &K) -> Option<&V> {
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

    fn put(&mut self, key: K, value: V) {
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
