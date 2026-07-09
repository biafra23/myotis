//! [`BlockContext`]: the verified block-level inputs a view call runs against.
//!
//! Mirrors the Java `BlockContext`. **Every field must come from the verified
//! header** — none may be sourced locally (a local clock for `timestamp`, say,
//! would desync the fork selection from consensus). `block_number` + `timestamp`
//! select the fork (see [`crate::fork`]); the rest feed EVM opcodes.

use revm::context::BlockEnv;
use revm::primitives::{Address, B256, U256};

/// Verified block-level context for one view call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockContext {
    /// State root the call's proofs verify against (SNAP view root). Not a fork
    /// or opcode input — it selects the world the [`crate::database::OracleDatabase`]
    /// reads.
    pub state_root: [u8; 32],
    /// Block number: NUMBER opcode, and pre-merge fork selection.
    pub block_number: u64,
    /// Unix-seconds timestamp: TIMESTAMP opcode, and post-merge fork selection.
    pub timestamp: u64,
    /// EIP-1559 base fee (wei): BASEFEE opcode. 0 pre-London (there is none).
    pub base_fee_per_gas: u64,
    /// Block proposer: COINBASE opcode.
    pub coinbase: [u8; 20],
    /// The header's mixHash slot = post-merge PREVRANDAO. The DIFFICULTY/PREVRANDAO
    /// opcode (0x44) reads this on every spec this engine serves (all post-merge).
    pub prev_randao: [u8; 32],
    /// EIP-155 chain id: CHAINID opcode (and the cfg chain id).
    pub chain_id: u64,
    /// Block gas limit: GASLIMIT opcode.
    pub gas_limit: u64,
}

impl BlockContext {
    /// The revm [`BlockEnv`] for this context.
    ///
    /// Post-merge (every spec this engine serves), the DIFFICULTY opcode reads
    /// `prevrandao`, so the `difficulty` field is unused and left 0 — which is also
    /// the true value in a post-merge header. It is deliberately NOT fed from the
    /// mixHash bytes: a pre-London..Paris block would then read a wrong difficulty,
    /// but such blocks aren't servable anyway (no snap state, outside the anchored
    /// head window). Likewise BLOBBASEFEE reads revm's default floor because
    /// `BlockContext` carries no excess-blob-gas field yet (matching the Java
    /// `BlockContextValues`, which maps no blob fields). Add a `difficulty` /
    /// `excess_blob_gas` field here if pre-merge or blob-fee `eth_call` is ever needed.
    pub fn block_env(&self) -> BlockEnv {
        BlockEnv {
            number: U256::from(self.block_number),
            timestamp: U256::from(self.timestamp),
            gas_limit: self.gas_limit,
            basefee: self.base_fee_per_gas,
            beneficiary: Address::from(self.coinbase),
            difficulty: U256::ZERO,
            prevrandao: Some(B256::from(self.prev_randao)),
            ..BlockEnv::default()
        }
    }
}
