//! The [`SnapStateOracle`] trait: the EVM's only source of world state.
//!
//! Mirrors the Java `io.myotis.evm.world.SnapStateOracle`. Every value an
//! implementation returns MUST be backed by an MPT proof that verified against
//! the caller-supplied `state_root` (accounts, storage) or a `keccak256(code)
//! == code_hash` check (bytecode). An implementation that cannot verify a value
//! returns [`OracleError`] — it NEVER returns unverified data. This is the trust
//! boundary of the whole engine, so the error set is *closed* (fail-closed):
//! callers must handle every case, and [`OracleError::InvalidProof`] is
//! security-critical.
//!
//! # Threading contract
//!
//! The trait is **synchronous**: `revm`'s `Database` is synchronous, and keeping
//! the bridge here (rather than an async trait the EVM would have to block on)
//! keeps this crate sans-I/O. A production implementation fetches over the
//! network, so its methods MAY BLOCK — callers MUST therefore run the EVM (and
//! hence these calls) on a worker thread, never a tokio reactor / UI thread. The
//! concrete async→sync bridge (blocking on the snap-peer fetch path) lives in the
//! I/O crate that implements this trait; this crate never spawns or blocks a
//! runtime itself.

use revm::primitives::U256;

use myotis_core::trie::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

/// A proof-verified account snapshot at a fixed `state_root`.
///
/// Carries `storage_root` — which `revm`'s own `AccountInfo` drops — because a
/// storage-slot proof anchors at the account's storage root, so a cached account
/// lets a later storage read skip re-fetching the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleAccount {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
}

impl OracleAccount {
    /// The account an *exclusion* proof verifies: nonce 0, zero balance, the
    /// empty-code hash, the empty-trie storage root. Returned for an address the
    /// proof shows is absent.
    pub fn empty() -> OracleAccount {
        OracleAccount {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_TRIE_ROOT,
        }
    }

    /// Whether this account has no contract code (an EOA or empty-code account) —
    /// its code is provably empty, so no bytecode fetch is needed.
    pub fn has_no_code(&self) -> bool {
        self.code_hash == EMPTY_CODE_HASH
    }
}

/// The closed, fail-closed error set an oracle may return. Mirrors the relevant
/// arm of the Java `EvmExecutionError`; the EVM-execution arms (Reverted,
/// OutOfGas, …) belong to the executor, added in a later Milestone-C slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OracleError {
    /// State for `address` (and `slot`, if a storage read) could not be fetched
    /// or verified against `state_root` — peers exhausted, transport failure, or
    /// no anchored head. Not necessarily an attack; retryable.
    StateUnavailable {
        state_root: [u8; 32],
        address: [u8; 20],
        slot: Option<[u8; 32]>,
    },
    /// No peer served bytecode hashing to `code_hash`. Retryable.
    BytecodeUnavailable { code_hash: [u8; 32] },
    /// An MPT proof FAILED to verify (or bytecode did not hash to its code hash).
    /// Security-critical: a peer served data inconsistent with the anchored root.
    /// Fail closed — surface, deprioritise the peer; never fall back to the value.
    InvalidProof {
        state_root: [u8; 32],
        address: [u8; 20],
        detail: String,
    },
    /// `BLOCKHASH` is unsupported (no local block store to serve historical
    /// hashes) — a contract that reads it cannot be executed. Fail fast.
    BlockHashUnsupported { number: u64 },
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OracleError::StateUnavailable { address, slot, .. } => match slot {
                Some(s) => write!(
                    f,
                    "state unavailable for 0x{}, slot 0x{}",
                    hex(address),
                    hex(s)
                ),
                None => write!(f, "state unavailable for 0x{}", hex(address)),
            },
            OracleError::BytecodeUnavailable { code_hash } => {
                write!(f, "bytecode unavailable for code hash 0x{}", hex(code_hash))
            }
            OracleError::InvalidProof {
                address, detail, ..
            } => {
                write!(f, "invalid proof for 0x{}: {detail}", hex(address))
            }
            OracleError::BlockHashUnsupported { number } => {
                write!(f, "BLOCKHASH unsupported (requested block {number})")
            }
        }
    }
}

impl std::error::Error for OracleError {}

// `revm`'s `Database::Error` bound. Marks our error as a database error type.
impl revm::database_interface::DBErrorMarker for OracleError {}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The verified world-state source the EVM reads through. See the module docs
/// for the verification and threading contract.
pub trait SnapStateOracle: Send + Sync {
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
}

#[cfg(any(test, feature = "fixture"))]
mod fixture {
    use super::*;
    use myotis_core::keccak::keccak256;
    use std::collections::HashMap;

    /// An in-memory [`SnapStateOracle`] for tests — no proofs, no network. Values
    /// are keyed by `(state_root, …)` so a test can assert the root actually
    /// selects the answer (a mismatched root reads as absent/zero). Mirrors the
    /// Java `FixtureSnapStateOracle`.
    #[derive(Default)]
    pub struct FixtureSnapStateOracle {
        accounts: HashMap<([u8; 32], [u8; 20]), OracleAccount>,
        storage: HashMap<([u8; 32], [u8; 20], [u8; 32]), U256>,
        bytecode: HashMap<[u8; 32], Vec<u8>>,
    }

    impl FixtureSnapStateOracle {
        pub fn new() -> FixtureSnapStateOracle {
            FixtureSnapStateOracle::default()
        }

        /// Add an account under `state_root`. Returns `self` for chaining.
        pub fn with_account(
            mut self,
            state_root: [u8; 32],
            address: [u8; 20],
            account: OracleAccount,
        ) -> Self {
            self.accounts.insert((state_root, address), account);
            self
        }

        /// Add a storage slot (raw 32-byte position) under `state_root`.
        pub fn with_storage(
            mut self,
            state_root: [u8; 32],
            address: [u8; 20],
            slot: [u8; 32],
            value: U256,
        ) -> Self {
            self.storage.insert((state_root, address, slot), value);
            self
        }

        /// Add bytecode, keyed by its own `keccak256`. Returns the code hash.
        pub fn with_bytecode(&mut self, code: Vec<u8>) -> [u8; 32] {
            let hash = keccak256(&code);
            self.bytecode.insert(hash, code);
            hash
        }
    }

    impl SnapStateOracle for FixtureSnapStateOracle {
        fn fetch_account(
            &self,
            state_root: &[u8; 32],
            address: [u8; 20],
        ) -> Result<Option<OracleAccount>, OracleError> {
            Ok(self.accounts.get(&(*state_root, address)).cloned())
        }

        fn fetch_storage(
            &self,
            state_root: &[u8; 32],
            address: [u8; 20],
            slot: U256,
        ) -> Result<U256, OracleError> {
            let key = slot.to_be_bytes::<32>();
            Ok(self
                .storage
                .get(&(*state_root, address, key))
                .copied()
                .unwrap_or(U256::ZERO))
        }

        fn fetch_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
            if code_hash == &EMPTY_CODE_HASH {
                return Ok(Vec::new());
            }
            self.bytecode
                .get(code_hash)
                .cloned()
                .ok_or(OracleError::BytecodeUnavailable {
                    code_hash: *code_hash,
                })
        }
    }
}

#[cfg(any(test, feature = "fixture"))]
pub use fixture::FixtureSnapStateOracle;
