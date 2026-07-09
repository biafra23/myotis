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
}

/// A `revm` state source backed by a verified oracle + the caches, pinned to one
/// block's `state_root`.
pub struct OracleDatabase {
    oracle: Arc<dyn SnapStateOracle>,
    state_root: [u8; 32],
    proof_cache: Arc<dyn StateProofCache>,
    bytecode_cache: Arc<dyn BytecodeCache>,
    view: Mutex<ViewCache>,
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
        }
    }

    /// Resolve an account through the three tiers. Returns the cached/ fetched
    /// account, or `None` when proven absent.
    fn account(&self, addr: [u8; 20]) -> Result<Option<OracleAccount>, OracleError> {
        // Tier 1 — this call.
        if let Some(cached) = self.view.lock().unwrap().accounts.get(&addr) {
            return Ok(cached.clone());
        }
        // Tier 2 — a verified fact from an earlier call at this root.
        if let Some(acc) = self.proof_cache.get_account(&self.state_root, &addr) {
            self.view
                .lock()
                .unwrap()
                .accounts
                .insert(addr, Some(acc.clone()));
            return Ok(Some(acc));
        }
        // Tier 3 — a fresh verified fetch. The lock is NOT held across it: the
        // oracle may block on the network, and a call runs single-threaded so
        // there is no concurrent view-cache writer to race.
        let fetched = self.oracle.fetch_account(&self.state_root, addr)?;
        if let Some(ref acc) = fetched {
            self.proof_cache.put_account(&self.state_root, &addr, acc);
        }
        self.view
            .lock()
            .unwrap()
            .accounts
            .insert(addr, fetched.clone());
        Ok(fetched)
    }
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
        if let Some(bytes) = self.bytecode_cache.get(&hash) {
            return Ok(Bytecode::new_raw(bytes));
        }
        let bytes: Bytes = self.oracle.fetch_bytecode(&hash)?.into();
        self.bytecode_cache.put(&hash, bytes.clone());
        Ok(Bytecode::new_raw(bytes))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let addr = address.into_array();
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
