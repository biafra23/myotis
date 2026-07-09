//! # myotis-evm
//!
//! The Rust EVM engine: `eth_call` / `estimateGas` over SNAP-proof-verified state,
//! built on [`revm`] behind a [`SnapStateOracle`] trait. Sans-I/O — this crate
//! holds no runtime, sockets, or clock; a synchronous oracle trait is the only
//! seam to the (async) snap-fetch path, and the bridge across it lives in the
//! implementing I/O crate.
//!
//! This is the Rust twin of the Java `io.myotis.evm` module (see
//! `docs/reimplementation/03` and the Milestone-C section of `…/07`). It is built
//! up over several PRs; **EL-C-1 (this slice)** lands the foundation only:
//!
//! * [`SnapStateOracle`] — the verified world-state trait, with an in-memory
//!   [`FixtureSnapStateOracle`] for tests;
//! * the cache tiers — [`StateProofCache`] (cross-call, `stateRoot`-keyed) and
//!   [`BytecodeCache`] (content-addressed, forever), plus a per-call view cache
//!   private to the adapter;
//! * [`OracleDatabase`] — the `revm` `DatabaseRef` adapter over the oracle and
//!   the caches.
//!
//! The view-call / gas-estimation executor, the mainnet fork table, the async
//! prefetch loop, and ENS/CCIP-Read arrive in the following Milestone-C slices.
//!
//! ## Wiring the EVM
//!
//! ```ignore
//! use std::sync::Arc;
//! use myotis_evm::{OracleDatabase, cache::{NoopStateProofCache, NoopBytecodeCache}};
//! use revm::database_interface::WrapDatabaseRef;
//! use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
//!
//! let db = OracleDatabase::new(
//!     oracle,                                  // Arc<dyn SnapStateOracle>
//!     state_root,                              // the block's beacon-anchored root
//!     Arc::new(NoopStateProofCache),
//!     Arc::new(NoopBytecodeCache),
//! );
//! let mut evm = Context::mainnet().with_db(WrapDatabaseRef(db)).build_mainnet();
//! // evm.transact(TxEnv::builder()…build_fill())  // EL-C-2
//! ```

pub mod cache;
pub mod database;
pub mod oracle;

pub use cache::{
    BytecodeCache, InMemoryBytecodeCache, InMemoryStateProofCache, NoopBytecodeCache,
    NoopStateProofCache, StateProofCache,
};
pub use database::OracleDatabase;
pub use oracle::{OracleAccount, OracleError, SnapStateOracle};

#[cfg(any(test, feature = "fixture"))]
pub use oracle::FixtureSnapStateOracle;

#[cfg(test)]
mod tests {
    use super::*;
    use revm::database_interface::DatabaseRef;
    use revm::primitives::{Address, B256, U256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use myotis_core::keccak::keccak256;
    use myotis_core::trie::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

    const ROOT_A: [u8; 32] = [0xAA; 32];
    const ROOT_B: [u8; 32] = [0xBB; 32];
    const ADDR: [u8; 20] = [0x11; 20];

    fn acct(balance: u64, nonce: u64, code_hash: [u8; 32]) -> OracleAccount {
        OracleAccount {
            nonce,
            balance: U256::from(balance),
            code_hash,
            storage_root: EMPTY_TRIE_ROOT,
        }
    }

    fn db(
        oracle: Arc<dyn SnapStateOracle>,
        root: [u8; 32],
        proofs: Arc<dyn StateProofCache>,
        codes: Arc<dyn BytecodeCache>,
    ) -> OracleDatabase {
        OracleDatabase::new(oracle, root, proofs, codes)
    }

    #[test]
    fn present_account_maps_to_account_info() {
        let oracle = Arc::new(FixtureSnapStateOracle::new().with_account(
            ROOT_A,
            ADDR,
            acct(1_000, 7, EMPTY_CODE_HASH),
        ));
        let d = db(
            oracle,
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let info = d.basic_ref(Address::from(ADDR)).unwrap().expect("present");
        assert_eq!(info.balance, U256::from(1_000));
        assert_eq!(info.nonce, 7);
        assert_eq!(info.code_hash, B256::from(EMPTY_CODE_HASH));
    }

    #[test]
    fn absent_account_is_none() {
        let oracle = Arc::new(FixtureSnapStateOracle::new());
        let d = db(
            oracle,
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        assert!(d.basic_ref(Address::from(ADDR)).unwrap().is_none());
    }

    #[test]
    fn state_root_selects_the_account() {
        // Same address, value only present under ROOT_A: a DB pinned to ROOT_B
        // must not see it (the root, not the address, is the key).
        let oracle = Arc::new(FixtureSnapStateOracle::new().with_account(
            ROOT_A,
            ADDR,
            acct(42, 0, EMPTY_CODE_HASH),
        ));
        let a = db(
            Arc::clone(&oracle) as Arc<dyn SnapStateOracle>,
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let b = db(
            oracle,
            ROOT_B,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        assert!(a.basic_ref(Address::from(ADDR)).unwrap().is_some());
        assert!(b.basic_ref(Address::from(ADDR)).unwrap().is_none());
    }

    #[test]
    fn storage_read_returns_value_and_zero_for_absent() {
        let mut slot0 = [0u8; 32];
        slot0[31] = 5; // position 5
        let oracle = Arc::new(FixtureSnapStateOracle::new().with_storage(
            ROOT_A,
            ADDR,
            slot0,
            U256::from(99),
        ));
        let d = db(
            oracle,
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        assert_eq!(
            d.storage_ref(Address::from(ADDR), U256::from(5)).unwrap(),
            U256::from(99)
        );
        assert_eq!(
            d.storage_ref(Address::from(ADDR), U256::from(6)).unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn empty_code_hash_short_circuits_without_fetch() {
        // A counting oracle proves code_by_hash never calls fetch_bytecode for the
        // empty hash.
        struct Counting(AtomicUsize);
        impl SnapStateOracle for Counting {
            fn fetch_account(
                &self,
                _r: &[u8; 32],
                _a: [u8; 20],
            ) -> Result<Option<OracleAccount>, OracleError> {
                Ok(None)
            }
            fn fetch_storage(
                &self,
                _r: &[u8; 32],
                _a: [u8; 20],
                _s: U256,
            ) -> Result<U256, OracleError> {
                Ok(U256::ZERO)
            }
            fn fetch_bytecode(&self, _h: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }
        let oracle = Arc::new(Counting(AtomicUsize::new(0)));
        let d = db(
            Arc::clone(&oracle) as Arc<dyn SnapStateOracle>,
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let code = d.code_by_hash_ref(B256::from(EMPTY_CODE_HASH)).unwrap();
        assert!(code.is_empty());
        assert_eq!(
            oracle.0.load(Ordering::SeqCst),
            0,
            "empty hash must not fetch"
        );
    }

    #[test]
    fn bytecode_is_content_addressed_and_cached() {
        let mut fixture = FixtureSnapStateOracle::new();
        let code = vec![0x60u8, 0x00, 0x60, 0x00, 0xf3]; // PUSH1 0 PUSH1 0 RETURN
        let hash = fixture.with_bytecode(code.clone());
        assert_eq!(hash, keccak256(&code));
        let codes = Arc::new(InMemoryBytecodeCache::new());
        let d = db(
            Arc::new(fixture),
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::clone(&codes) as Arc<dyn BytecodeCache>,
        );
        let bc = d.code_by_hash_ref(B256::from(hash)).unwrap();
        assert_eq!(bc.original_bytes().as_ref(), code.as_slice());
        // Second read is served from the bytecode cache (now populated).
        assert!(codes.get(&hash).is_some());
        assert_eq!(
            d.code_by_hash_ref(B256::from(hash))
                .unwrap()
                .original_bytes()
                .as_ref(),
            code
        );
    }

    #[test]
    fn missing_bytecode_is_fail_closed() {
        let d = db(
            Arc::new(FixtureSnapStateOracle::new()),
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let err = d.code_by_hash_ref(B256::from([0x77u8; 32])).unwrap_err();
        assert!(matches!(err, OracleError::BytecodeUnavailable { .. }));
    }

    #[test]
    fn blockhash_is_unsupported() {
        let d = db(
            Arc::new(FixtureSnapStateOracle::new()),
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        assert!(matches!(
            d.block_hash_ref(21_000_000).unwrap_err(),
            OracleError::BlockHashUnsupported { number: 21_000_000 }
        ));
    }

    #[test]
    fn revm_executes_a_contract_reading_verified_storage() {
        // End-to-end: a real revm run of an SLOAD-and-return contract, driven
        // entirely through OracleDatabase. Proves the DatabaseRef adapter is the
        // correct shape for revm's executor (and de-risks the EL-C-2 eth_call).
        use revm::context::TxEnv;
        use revm::database_interface::WrapDatabaseRef;
        use revm::primitives::TxKind;
        use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

        // PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — returns slot 0.
        let code = vec![
            0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let code_hash = keccak256(&code);
        let slot0 = [0u8; 32]; // storage position 0
        let mut fixture = FixtureSnapStateOracle::new()
            .with_account(
                ROOT_A,
                ADDR,
                OracleAccount {
                    nonce: 1,
                    balance: U256::ZERO,
                    code_hash,
                    storage_root: [0x01; 32],
                },
            )
            .with_storage(ROOT_A, ADDR, slot0, U256::from(0xdead_beefu64));
        assert_eq!(fixture.with_bytecode(code), code_hash);

        let d = db(
            Arc::new(fixture),
            ROOT_A,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let mut evm = Context::mainnet()
            .with_db(WrapDatabaseRef(d))
            .build_mainnet();
        // gas_limit under the latest spec's per-tx cap (EIP-7825, 2^24); the 30 M
        // eth_call ceiling + fork/cfg selection is EL-C-2's concern.
        let tx = TxEnv::builder()
            .caller(Address::ZERO)
            .kind(TxKind::Call(Address::from(ADDR)))
            .gas_limit(1_000_000)
            .build_fill();
        let out = evm.transact(tx).expect("execution");
        let data = out.result.output().expect("output").to_vec();
        assert_eq!(data.len(), 32);
        assert_eq!(U256::from_be_slice(&data), U256::from(0xdead_beefu64));
    }

    #[test]
    fn cross_call_cache_serves_without_a_second_fetch() {
        // An oracle that fails after its first account fetch: a second read must be
        // served from the cross-call cache, proving tier 2 short-circuits the oracle.
        struct OneShot {
            calls: AtomicUsize,
            acc: OracleAccount,
        }
        impl SnapStateOracle for OneShot {
            fn fetch_account(
                &self,
                _r: &[u8; 32],
                _a: [u8; 20],
            ) -> Result<Option<OracleAccount>, OracleError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(Some(self.acc.clone()))
                } else {
                    Err(OracleError::StateUnavailable {
                        state_root: ROOT_A,
                        address: ADDR,
                        slot: None,
                    })
                }
            }
            fn fetch_storage(
                &self,
                _r: &[u8; 32],
                _a: [u8; 20],
                _s: U256,
            ) -> Result<U256, OracleError> {
                Ok(U256::ZERO)
            }
            fn fetch_bytecode(&self, _h: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
                Ok(Vec::new())
            }
        }
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
}
