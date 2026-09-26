//! [`EvmError`]: the closed outcome set of a view call.
//!
//! Wraps the state-fetch failures ([`OracleError`], surfaced from the revm
//! `Database`) and adds the execution outcomes an `eth_call` can produce. Like
//! [`OracleError`] it is fail-closed: a caller must handle every arm, and a
//! revert carries its raw data so the JSON-RPC layer can echo it.

use crate::oracle::OracleError;

/// Everything a view call can return other than the success bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmError {
    /// State could not be fetched or verified (from the oracle / revm `Database`)
    /// — includes `BlockHashUnsupported`. See [`OracleError`].
    Oracle(OracleError),
    /// The contract reverted. `data` is the raw revert payload (a Solidity
    /// `Error(string)` is ABI-encoded behind the `0x08c379a0` selector).
    Reverted { data: Vec<u8> },
    /// The call ran out of gas within the 30 M ceiling.
    OutOfGas,
    /// The EVM halted for another reason (invalid opcode, stack error, …). The
    /// string is revm's `HaltReason` debug form — diagnostic, not a stable token.
    Halted { reason: String },
    /// The target block predates London; the engine does not execute pre-London
    /// state (no local archive, and the fork rules below London aren't modelled).
    ForkTooOld { block_number: u64, timestamp: u64 },
    /// The block context is for a chain this executor can't run. The fork table is
    /// mainnet-only, so a non-mainnet chain id would otherwise get mainnet forks —
    /// fail closed instead of returning a silently-wrong result. (Multichain support
    /// makes the fork table chain-aware and relaxes this.)
    UnsupportedChain { chain_id: u64 },
    /// revm rejected the transaction envelope itself (should not happen for a
    /// well-formed view call — surfaced rather than swallowed).
    Transaction { detail: String },
    /// The speculative prefetch convergence loop didn't settle within its
    /// iteration cap (Java `IterationLimitExceeded` twin) — fail closed rather
    /// than answer from a run that was still discovering state.
    IterationLimitExceeded { cap: usize },
    /// The fork table puts this block at AMSTERDAM or later, but its header
    /// carried no EIP-7843 slot number, so SLOTNUM could only read a made-up
    /// value. Consensus requires the field on every Amsterdam header, so a
    /// verified header without it means the block isn't what the fork table
    /// says (e.g. the fork was postponed after this build shipped) — no retry
    /// can fix that. A refusal ([`EvmError::is_refusal`]).
    MissingSlotNumber { block_number: u64 },
    /// The mirror image: the header carries an EIP-7843 slot number, which only
    /// Amsterdam headers have, but the fork table puts the block before
    /// AMSTERDAM — the network scheduled or moved the fork after this build
    /// shipped. Running it under the older fork's opcodes and gas model would
    /// be a well-formed wrong answer, and no retry can fix that. A refusal
    /// ([`EvmError::is_refusal`]).
    UnexpectedSlotNumber { block_number: u64 },
}

impl EvmError {
    /// True when this call can never be answered on this build: hosts must
    /// serve a PERMANENT error (JSON-RPC -32602), never the retryable
    /// "unavailable" a client would spin on (CLAUDE.md apply-or-refuse).
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            EvmError::MissingSlotNumber { .. } | EvmError::UnexpectedSlotNumber { .. }
        )
    }
}

impl From<OracleError> for EvmError {
    fn from(e: OracleError) -> EvmError {
        EvmError::Oracle(e)
    }
}

impl std::fmt::Display for EvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvmError::Oracle(e) => write!(f, "{e}"),
            EvmError::Reverted { data } => {
                write!(f, "execution reverted ({} bytes of data)", data.len())
            }
            EvmError::OutOfGas => write!(f, "out of gas"),
            EvmError::Halted { reason } => write!(f, "execution halted: {reason}"),
            EvmError::ForkTooOld { block_number, timestamp } => write!(
                f,
                "pre-London blocks are not supported (blockNumber={block_number}, timestamp={timestamp})"
            ),
            EvmError::UnsupportedChain { chain_id } => {
                write!(f, "unsupported chain id {chain_id} (executor is mainnet-only)")
            }
            EvmError::Transaction { detail } => write!(f, "invalid transaction: {detail}"),
            EvmError::IterationLimitExceeded { cap } => write!(
                f,
                "call did not converge within {cap} prefetch iterations"
            ),
            EvmError::MissingSlotNumber { block_number } => write!(
                f,
                "block {block_number} is an Amsterdam block but its header has no slot number \
                 (EIP-7843); refusing to run SLOTNUM against a made-up value"
            ),
            EvmError::UnexpectedSlotNumber { block_number } => write!(
                f,
                "block {block_number} carries an EIP-7843 slot number, so it is an Amsterdam \
                 block, but this build's fork table puts it before Amsterdam; refusing to run \
                 it under the older fork's rules"
            ),
        }
    }
}

impl std::error::Error for EvmError {}
