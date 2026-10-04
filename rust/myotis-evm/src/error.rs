//! [`EvmError`]: the closed outcome set of a view call.
//!
//! Wraps the state-fetch failures ([`OracleError`], surfaced from the revm
//! `Database`) and adds the execution outcomes an `eth_call` can produce. Like
//! [`OracleError`] it is fail-closed: a caller must handle every arm, and a
//! revert carries its raw data so the JSON-RPC layer can echo it.

use crate::oracle::OracleError;
use revm::primitives::{Address, U256};

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
    /// The block context is for a chain this executor has no fork table for (the
    /// table covers mainnet, Sepolia and Gnosis), so any other chain id would
    /// otherwise run under another chain's forks — fail closed instead of returning
    /// a silently-wrong result.
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
    /// The request's transaction object is one no transaction could be (a
    /// type-4 request without an authorization list, a tip above its fee cap,
    /// a `chainId` for another chain, …): refused before any state is read,
    /// never "repaired" into a different transaction ([`crate::tx::TxRequest::validate`]).
    /// A refusal ([`EvmError::is_refusal`]) — no retry changes the request.
    InvalidRequest { detail: String },
    /// `eth_estimateGas`: the transaction does not succeed within the gas the
    /// caller allowed — its `gas`, the funds its fee cap can pay for, or this
    /// executor's own ceiling, whichever is lowest. A deterministic ANSWER, not
    /// a failure to answer; the message is geth's, so a wallet reads it the
    /// same way from this node as from a public one ([`EvmError::is_infeasible`]).
    GasAllowanceExceeded { allowance: u64 },
    /// `eth_estimateGas` with a fee cap: the sender cannot even cover the
    /// transferred value (geth's `insufficient funds for transfer`). An answer
    /// like [`EvmError::GasAllowanceExceeded`] ([`EvmError::is_infeasible`]).
    InsufficientFundsForTransfer,
    /// `eth_call` with a fee: the sender cannot pay `gas × fee cap + value`
    /// (geth's `insufficient funds for gas * price + value`). An answer about
    /// the request ([`EvmError::is_infeasible`]).
    InsufficientFunds { address: [u8; 20], have: U256, want: U256 },
    /// A fee cap (or legacy gas price) below the block's base fee: no block at
    /// that base fee includes the transaction, so geth answers
    /// `max fee per gas less than block base fee` for both a call and an
    /// estimate ([`EvmError::is_infeasible`]).
    FeeCapTooLow { address: [u8; 20], fee_cap: u128, base_fee: u64 },
    /// `eth_call` with a `gas` below the transaction's intrinsic cost (geth's
    /// `intrinsic gas too low`; an estimate reads it as
    /// [`EvmError::GasAllowanceExceeded`] instead, as geth does).
    IntrinsicGasTooLow { have: u64, want: u64 },
    /// `eth_call` with a `gas` below the EIP-7623 calldata floor (geth's
    /// `insufficient gas for floor data gas cost`; an estimate reads it as
    /// [`EvmError::GasAllowanceExceeded`]).
    FloorDataGasTooLow { have: u64, want: u64 },
    /// `eth_call` ran out of the `gas` the caller gave it (geth's `out of
    /// gas`). Without a caller limit a call that runs dry is
    /// [`EvmError::OutOfGas`], as before.
    CallOutOfGas,
    /// An estimate whose run at its ceiling `gas` was refused outright (a fee
    /// cap below the base fee): geth's estimator wraps the state transition's
    /// error as `failed with {gas} gas: {error}`, and so do we
    /// ([`EvmError::is_infeasible`]).
    FailedWithGas { gas: u64, error: Box<EvmError> },
    /// `eth_call` with `gas × fee cap + value` past 2^256 wei: geth's
    /// `insufficient funds for gas * price + value: address … required
    /// balance exceeds 256 bits` ([`EvmError::is_infeasible`]).
    RequiredBalanceOverflow { address: [u8; 20] },
    /// `eth_call` whose `gas` was above the call budget, capped to it, and
    /// ran out there: the answer says nothing about the limit the caller set,
    /// so it is refused ([`EvmError::is_refusal`]) — never answered for a
    /// smaller limit, nor served as the retryable unavailable a client would
    /// spin on.
    CallBudgetExceeded { budget: u64, requested: u64 },
    /// `eth_call` refused by one of the checks a transaction passes before it
    /// runs (fee cap, balance, intrinsic cost, floor): geth's `eth_call` wraps
    /// the state transition's error as `err: {error} (supplied gas {gas})`, and
    /// so do we ([`EvmError::is_infeasible`]).
    CallFailed { supplied_gas: u64, error: Box<EvmError> },
}

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

impl EvmError {
    /// The error's kind, without the values it carries (an address, a
    /// balance, revert data): what a log line at info may name (#532 review).
    /// An oracle error is named by its own kind ([`OracleError::kind`]), so a
    /// request that ran out of time and a proof that failed are told apart.
    pub fn kind(&self) -> &'static str {
        match self {
            EvmError::Oracle(error) => error.kind(),
            EvmError::Reverted { .. } => "reverted",
            EvmError::OutOfGas => "out of gas",
            EvmError::Halted { .. } => "halted",
            EvmError::ForkTooOld { .. } => "fork too old",
            EvmError::UnsupportedChain { .. } => "unsupported chain",
            EvmError::Transaction { .. } => "transaction",
            EvmError::IterationLimitExceeded { .. } => "iteration limit exceeded",
            EvmError::MissingSlotNumber { .. } => "missing slot number",
            EvmError::UnexpectedSlotNumber { .. } => "unexpected slot number",
            EvmError::InvalidRequest { .. } => "invalid request",
            EvmError::GasAllowanceExceeded { .. } => "gas allowance exceeded",
            EvmError::InsufficientFundsForTransfer => "insufficient funds for transfer",
            EvmError::InsufficientFunds { .. } => "insufficient funds",
            EvmError::FeeCapTooLow { .. } => "fee cap too low",
            EvmError::IntrinsicGasTooLow { .. } => "intrinsic gas too low",
            EvmError::FloorDataGasTooLow { .. } => "floor data gas too low",
            EvmError::CallOutOfGas => "call out of gas",
            EvmError::FailedWithGas { error, .. } | EvmError::CallFailed { error, .. } => error.kind(),
            EvmError::RequiredBalanceOverflow { .. } => "required balance overflow",
            EvmError::CallBudgetExceeded { .. } => "call budget exceeded",
        }
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
                write!(f, "unsupported chain id {chain_id} (no fork table: the executor runs mainnet, sepolia and gnosis)")
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
            EvmError::InvalidRequest { detail } => write!(f, "invalid transaction object: {detail}"),
            // geth's exact messages (gasestimator / core.ErrInsufficientFundsForTransfer):
            // wallets match on them.
            EvmError::GasAllowanceExceeded { allowance } => {
                write!(f, "gas required exceeds allowance ({allowance})")
            }
            EvmError::InsufficientFundsForTransfer => write!(f, "insufficient funds for transfer"),
            // geth's core errors, formatted as its state transition formats them
            // (the address EIP-55 checksummed, as `common.Address.Hex()` prints it).
            EvmError::InsufficientFunds { address, have, want } => write!(
                f,
                "insufficient funds for gas * price + value: address {} have {have} want {want}",
                Address::from(*address)
            ),
            EvmError::FeeCapTooLow { address, fee_cap, base_fee } => write!(
                f,
                "max fee per gas less than block base fee: address {}, maxFeePerGas: {fee_cap}, baseFee: {base_fee}",
                Address::from(*address)
            ),
            EvmError::IntrinsicGasTooLow { have, want } => {
                write!(f, "intrinsic gas too low: have {have}, want {want}")
            }
            EvmError::FloorDataGasTooLow { have, want } => {
                write!(f, "insufficient gas for floor data gas cost: have {have}, want {want}")
            }
            EvmError::CallOutOfGas => write!(f, "out of gas"),
            EvmError::FailedWithGas { gas, error } => write!(f, "failed with {gas} gas: {error}"),
            EvmError::RequiredBalanceOverflow { address } => write!(
                f,
                "insufficient funds for gas * price + value: address {} required balance exceeds 256 bits",
                Address::from(*address)
            ),
            EvmError::CallBudgetExceeded { budget, requested } => write!(
                f,
                "the call ran out of this node's {budget}-gas call budget, below the {requested} gas it allows"
            ),
            EvmError::CallFailed { supplied_gas, error } => {
                write!(f, "err: {error} (supplied gas {supplied_gas})")
            }
        }
    }
}

impl std::error::Error for EvmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kind_names_the_error_never_its_values() {
        // #532 review: the call breakdown logs at info, so it names an error's
        // kind and leaves its values (here an address) out. A wrapped error
        // is named by what it wraps.
        let funds = EvmError::InsufficientFunds { address: [0xab; 20], have: U256::from(1u64), want: U256::from(2u64) };
        assert!(funds.to_string().contains("abab"), "{funds}");
        assert_eq!(funds.kind(), "insufficient funds");
        let call = EvmError::CallFailed { supplied_gas: 21_000, error: Box::new(funds) };
        assert_eq!(call.kind(), "insufficient funds");
        let revert = EvmError::Reverted { data: vec![0xde, 0xad] };
        let estimate = EvmError::FailedWithGas { gas: 50_000, error: Box::new(revert) };
        assert_eq!(estimate.kind(), "reverted");
        // An oracle error by its own kind: a cut request is not a bad proof.
        let cut = EvmError::Oracle(OracleError::Cancelled { reason: "request deadline exceeded".into() });
        assert_eq!(cut.kind(), "request deadline exceeded");
        // Any other reason is a plain cancellation: its text is not logged.
        let other = OracleError::Cancelled { reason: "peer 0xabab… went away".into() };
        assert_eq!(EvmError::Oracle(other).kind(), "request cancelled");
        let proof = OracleError::InvalidProof { state_root: [1; 32], address: [0xab; 20], detail: "root mismatch".into() };
        assert_eq!(EvmError::Oracle(proof).kind(), "invalid proof");
    }
}
