//! [`EvmExecutor`]: `eth_call` over proof-verified state.
//!
//! Runs a read-only call against the SNAP-verified world exposed by a
//! [`SnapStateOracle`], at the fork the block's `(number, timestamp)` selects.
//! Nothing is committed — a fresh [`OracleDatabase`] is built per call and
//! discarded, and revm's journal is thrown away.
//!
//! ## Why the checks are relaxed
//!
//! A view call is not a real transaction: the sender need not exist, hold a
//! balance, or pay the base fee, and it gets the full block-sized gas allowance.
//! We therefore run with revm's `CfgEnv` disables — balance, nonce, base fee,
//! EIP-3607 (sender-has-code), block gas limit — matching the Java executor,
//! which drives the message processor directly and so performs none of the
//! transaction-level validations. The call is deliberately NON-static
//! (`is_static` unset) so a simulated `SSTORE` (every ERC-20 `transfer`/`approve`)
//! doesn't halt — the writes journal into the per-call state and are discarded.
//!
//! EIP-7702 one-hop delegation is handled by revm itself: the oracle serves the
//! delegation designator as the account's code, and revm resolves the one hop to
//! the delegate's code (fetched, again, through the oracle). BLOCKHASH is
//! unsupported — the `Database` returns an error, surfaced as [`EvmError`].

use std::sync::Arc;

use revm::context::result::{ExecutionResult, HaltReason, Output};
use revm::context::{CfgEnv, TxEnv};
use revm::database_interface::{DBErrorMarker, DatabaseRef};
use revm::primitives::{Address, TxKind, U256};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

use crate::block::BlockContext;
use crate::cache::{BytecodeCache, StateProofCache};
use crate::database::OracleDatabase;
use crate::error::EvmError;
use crate::fork::spec_for;
use crate::oracle::{OracleError, SnapStateOracle};

/// The gas a view call is given — the mainnet block gas limit. Also set as the
/// per-tx gas cap so revm's spec-default cap (2²⁴ on the latest fork, EIP-7825)
/// doesn't clip an `eth_call` that legitimately wants the full block budget.
pub const VIEW_CALL_GAS: u64 = 30_000_000;

/// The exact intrinsic cost of a plain value transfer — the empty-calldata
/// no-code estimate short-circuit's answer (unbuffered; Java parity).
const PLAIN_TRANSFER_GAS: u64 = 21_000;

/// The from-less `eth_call` sender: the zero address (Geth's default). A caller
/// that needs `msg.sender` set (ERC-20 `transfer`/`approve`) uses [`EvmExecutor::call_view_from`].
const VIEW_CALLER: Address = Address::ZERO;

/// Executes view calls against verified state. Owns the shared cross-call caches,
/// so repeated calls (e.g. a MetaMask number-pinned retry) reuse verified facts.
pub struct EvmExecutor {
    oracle: Arc<dyn SnapStateOracle>,
    proof_cache: Arc<dyn StateProofCache>,
    bytecode_cache: Arc<dyn BytecodeCache>,
}

impl EvmExecutor {
    pub fn new(
        oracle: Arc<dyn SnapStateOracle>,
        proof_cache: Arc<dyn StateProofCache>,
        bytecode_cache: Arc<dyn BytecodeCache>,
    ) -> EvmExecutor {
        EvmExecutor {
            oracle,
            proof_cache,
            bytecode_cache,
        }
    }

    /// `eth_call` with a from-less, zero-value anonymous sender.
    pub fn call_view(
        &self,
        target: [u8; 20],
        calldata: &[u8],
        ctx: &BlockContext,
    ) -> Result<Vec<u8>, EvmError> {
        self.call(VIEW_CALLER, target, calldata, U256::ZERO, ctx)
    }

    /// `eth_call` with an explicit `sender` and `value` — needed so `msg.sender`-
    /// gated contracts don't revert against the zero address.
    pub fn call_view_from(
        &self,
        sender: [u8; 20],
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<Vec<u8>, EvmError> {
        self.call(Address::from(sender), target, calldata, value, ctx)
    }

    /// `estimateGas` for a call (`to` != null): run it and return the gas LIMIT that
    /// would let it succeed. Reverts/halts yield no number (an `Err`) — the host
    /// maps that to a JSON-RPC null, like the reference engine.
    pub fn estimate_gas(
        &self,
        from: [u8; 20],
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<u64, EvmError> {
        self.estimate(Address::from(from), target, calldata, value, ctx)
    }

    /// The shared setup + `transact`, returning revm's raw result. Only DB / tx-
    /// envelope failures become `Err` here; execution outcomes (success/revert/halt)
    /// are returned for the caller to interpret.
    fn execute(
        &self,
        caller: Address,
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<ExecutionResult, EvmError> {
        // Chain-aware fork selection: an unknown chain id fails closed with
        // UnsupportedChain inside spec_for (never silently mainnet rules). The
        // `Context::mainnet()` builder below is chain-neutral standard-Ethereum
        // rules — the chain id itself is set via cfg.chain_id, and every chain
        // spec_for knows (mainnet, sepolia) is rule-identical at a given SpecId.
        let spec = spec_for(ctx.chain_id, ctx.block_number, ctx.timestamp)?;

        let db = OracleDatabase::new(
            Arc::clone(&self.oracle),
            ctx.state_root,
            Arc::clone(&self.proof_cache),
            Arc::clone(&self.bytecode_cache),
        );

        let mut cfg = CfgEnv::new_with_spec(spec);
        cfg.chain_id = ctx.chain_id;
        // Not a real tx: relax the transaction-level checks (see the module docs).
        // `tx_gas_limit_cap` is raised to VIEW_CALL_GAS so the spec's own per-tx cap
        // doesn't clip the full-block gas budget (also the estimate ceiling).
        cfg.disable_nonce_check = true;
        cfg.disable_balance_check = true;
        cfg.disable_base_fee = true;
        cfg.disable_eip3607 = true;
        cfg.disable_block_gas_limit = true;
        cfg.tx_gas_limit_cap = Some(VIEW_CALL_GAS);

        let tx = TxEnv::builder()
            .caller(caller)
            .kind(TxKind::Call(Address::from(target)))
            .value(value)
            .data(calldata.to_vec().into())
            .gas_limit(VIEW_CALL_GAS)
            // Explicit: build_fill() defaults the tx chain id to MAINNET (Some(1)),
            // which revm validates against cfg.chain_id — on any other chain the
            // call would die with "invalid chain ID" (found live on sepolia).
            .chain_id(Some(ctx.chain_id))
            .build_fill();

        let mut evm = Context::mainnet()
            .with_ref_db(db)
            .with_block(ctx.block_env())
            .with_cfg(cfg)
            .build_mainnet();

        Ok(evm.transact(tx).map_err(map_evm_error)?.result)
    }

    /// Run a call and return its output bytes (revert/halt → `Err`).
    fn call(
        &self,
        caller: Address,
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<Vec<u8>, EvmError> {
        match self.execute(caller, target, calldata, value, ctx)? {
            ExecutionResult::Success { output, .. } => Ok(output_bytes(output)),
            ExecutionResult::Revert { output, .. } => {
                Err(EvmError::Reverted { data: output.to_vec() })
            }
            ExecutionResult::Halt { reason, .. } => Err(map_halt(reason)),
        }
    }

    /// Run a call and return the gas-limit estimate (revert/halt → `Err`).
    fn estimate(
        &self,
        caller: Address,
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<u64, EvmError> {
        // Java `rpcEstimateGas` parity: a plain transfer (empty calldata) to a
        // CODELESS account costs exactly 21000 — no EVM run and NO 1.15 buffer
        // (it's exact). One verified account fetch through the caching database
        // decides it; an account WITH code (contract, or an EIP-7702-delegated
        // EOA) falls through to the full estimate. Fork/chain validation still
        // runs FIRST — an unsupported chain or too-old fork fails closed here
        // exactly like the full path, never answering 21000 for a context the
        // executor wouldn't execute.
        spec_for(ctx.chain_id, ctx.block_number, ctx.timestamp)?;
        if calldata.is_empty() {
            let db = OracleDatabase::new(
                Arc::clone(&self.oracle),
                ctx.state_root,
                Arc::clone(&self.proof_cache),
                Arc::clone(&self.bytecode_cache),
            );
            let no_code = db
                .basic_ref(Address::from(target))?
                .is_none_or(|a| a.code_hash.0 == myotis_core::trie::EMPTY_CODE_HASH);
            if no_code {
                return Ok(PLAIN_TRANSFER_GAS);
            }
        }
        match self.execute(caller, target, calldata, value, ctx)? {
            ExecutionResult::Success { gas, .. } => {
                // The gas-limit base must cover BOTH the gross execution draw
                // (`total_gas_spent`, before the EIP-3529 refund — so the run never
                // OOGs mid-execution) AND the EIP-7623 calldata floor (`tx_gas_used`
                // = max(spent−refund, floor_gas) — the minimum a Prague+ tx is
                // charged). `max(total_gas_spent, tx_gas_used)` == `max(gross, floor)`.
                let base = gas.total_gas_spent().max(gas.tx_gas_used());
                Ok(with_estimate_buffer(base))
            }
            ExecutionResult::Revert { output, .. } => {
                Err(EvmError::Reverted { data: output.to_vec() })
            }
            ExecutionResult::Halt { reason, .. } => Err(map_halt(reason)),
        }
    }
}

fn output_bytes(output: Output) -> Vec<u8> {
    output.into_data().to_vec()
}

/// Apply the 1.15 headroom buffer to a gas base, rounded up (mirrors the Java
/// engine's `ceil(total * 1.15)`). `base <= 30 M`, so `* 115` never overflows u64,
/// but the u128 math + clamp keeps it panic-free regardless.
fn with_estimate_buffer(base: u64) -> u64 {
    let scaled = (base as u128 * 115).div_ceil(100);
    scaled.min(u64::MAX as u128) as u64
}

fn map_halt(reason: HaltReason) -> EvmError {
    match reason {
        HaltReason::OutOfGas(_) => EvmError::OutOfGas,
        other => EvmError::Halted {
            reason: format!("{other:?}"),
        },
    }
}

/// Map revm's top-level error into [`EvmError`]. A `Database` error is our
/// [`OracleError`] (state couldn't be fetched/verified); a `Transaction` error is
/// an envelope rejection we surface rather than swallow.
fn map_evm_error<E: DBErrorMarker + Into<EvmError> + std::fmt::Display>(
    err: revm::context::result::EVMError<E>,
) -> EvmError {
    use revm::context::result::EVMError;
    match err {
        EVMError::Database(e) => e.into(),
        other => EvmError::Transaction {
            detail: other.to_string(),
        },
    }
}

// Ensure the DB error the executor threads is exactly OracleError (a compile-time
// guard: if OracleDatabase's Error type ever diverges, `run` stops compiling).
const _: fn() = || {
    fn assert_db_error<T: DBErrorMarker + Into<EvmError>>() {}
    assert_db_error::<OracleError>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{NoopBytecodeCache, NoopStateProofCache};
    use crate::fork::{CANCUN_TIME, LONDON_BLOCK};
    use crate::oracle::{FixtureSnapStateOracle, OracleAccount};
    use myotis_core::keccak::keccak256;

    const ROOT: [u8; 32] = [0xAA; 32];
    const TARGET: [u8; 20] = [0x11; 20];

    fn ctx(block: u64, ts: u64) -> BlockContext {
        BlockContext {
            state_root: ROOT,
            block_number: block,
            timestamp: ts,
            base_fee_per_gas: 7, // non-zero: proves disable_base_fee lets a 0-price call run
            coinbase: [0x22; 20],
            prev_randao: [0x33; 32],
            chain_id: 1,
            gas_limit: 30_000_000,
        }
    }

    /// Build an executor whose fixture hosts `code` (and optional slot-0 value) at
    /// TARGET, with Noop caches.
    fn executor_with(code: Vec<u8>, slot0: Option<U256>) -> EvmExecutor {
        let ch = keccak256(&code);
        let mut fx = FixtureSnapStateOracle::new().with_account(
            ROOT,
            TARGET,
            OracleAccount {
                nonce: 1,
                balance: U256::ZERO,
                code_hash: ch,
                storage_root: [0x9; 32],
            },
        );
        assert_eq!(fx.with_bytecode(code), ch);
        if let Some(v) = slot0 {
            fx = fx.with_storage(ROOT, TARGET, [0u8; 32], v);
        }
        EvmExecutor::new(
            Arc::new(fx),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        )
    }

    #[test]
    fn cancun_call_returns_verified_storage_uint256() {
        // Mirrors the Java EvmFactoryTest: Cancun EVM, SLOAD slot 0 → return 32
        // bytes. PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN.
        let code = vec![
            0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let exec = executor_with(code, Some(U256::from(12_345_678_900_000_000_000_000u128)));
        let out = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(
            U256::from_be_slice(&out),
            U256::from(12_345_678_900_000_000_000_000u128)
        );
    }

    #[test]
    fn from_overload_sets_msg_sender() {
        // CALLER PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — returns msg.sender.
        let code = vec![0x33u8, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, None);
        let sender = [0x42u8; 20];
        let out = exec
            .call_view_from(
                sender,
                TARGET,
                &[],
                U256::ZERO,
                &ctx(19_500_000, CANCUN_TIME + 1),
            )
            .unwrap();
        assert_eq!(
            &out[12..32],
            &sender,
            "msg.sender must be the supplied from"
        );
        // The from-less overload is the zero address.
        let anon = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert_eq!(U256::from_be_slice(&anon), U256::ZERO);
    }

    #[test]
    fn callvalue_is_passed_through() {
        // CALLVALUE PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — returns msg.value.
        let code = vec![0x34u8, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, None);
        let out = exec
            .call_view_from(
                [0x1; 20],
                TARGET,
                &[],
                U256::from(777),
                &ctx(19_500_000, CANCUN_TIME + 1),
            )
            .unwrap();
        assert_eq!(U256::from_be_slice(&out), U256::from(777));
    }

    #[test]
    fn prevrandao_opcode_returns_context_value() {
        // PREVRANDAO PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — opcode 0x44 reads
        // prevrandao post-merge; must be the context's prev_randao ([0x33; 32]).
        let code = vec![0x44u8, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, None);
        let out = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert_eq!(out.as_slice(), &[0x33u8; 32]);
    }

    #[test]
    fn revert_surfaces_raw_data() {
        // PUSH1 0xAB PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 REVERT.
        let code = vec![0x60u8, 0xAB, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xfd];
        let exec = executor_with(code, None);
        let err = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap_err();
        match err {
            EvmError::Reverted { data } => {
                assert_eq!(data.len(), 32);
                assert_eq!(data.last(), Some(&0xABu8));
            }
            other => panic!("expected revert, got {other:?}"),
        }
    }

    #[test]
    fn out_of_gas_is_reported() {
        // An unbounded loop: JUMPDEST PUSH1 0 JUMP (0x5b 0x60 0x00 0x56) spins until
        // the 30 M gas runs out.
        let code = vec![0x5bu8, 0x60, 0x00, 0x56];
        let exec = executor_with(code, None);
        let err = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap_err();
        assert!(matches!(err, EvmError::OutOfGas), "got {err:?}");
    }

    #[test]
    fn plain_transfer_to_codeless_account_is_exactly_21000() {
        // Empty calldata + no code → the short-circuit answers 21000 EXACTLY
        // (no 1.15 buffer, no EVM run — Java rpcEstimateGas parity).
        let fx = FixtureSnapStateOracle::new().with_account(
            ROOT,
            TARGET,
            OracleAccount {
                nonce: 1,
                balance: U256::from(1_000_000u64),
                code_hash: myotis_core::trie::EMPTY_CODE_HASH,
                storage_root: [0x9; 32],
            },
        );
        let exec = EvmExecutor::new(
            Arc::new(fx),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let est = exec
            .estimate_gas([0x42; 20], TARGET, &[], U256::from(1u64), &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert_eq!(est, 21_000);
    }

    #[test]
    fn plain_transfer_to_absent_account_is_exactly_21000() {
        // A proven-absent recipient has no code either — same exact answer.
        // The fixture treats any un-added account as proven ABSENT.
        let fx = FixtureSnapStateOracle::new();
        let exec = EvmExecutor::new(
            Arc::new(fx),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let est = exec
            .estimate_gas([0x42; 20], TARGET, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert_eq!(est, 21_000);
    }

    #[test]
    fn oracle_failure_during_short_circuit_is_an_error_not_21000() {
        // State unavailable must NEVER read as "no code → 21000" — that would
        // hand out a plausible number for a recipient we couldn't verify.
        struct FailingOracle;
        impl crate::oracle::SnapStateOracle for FailingOracle {
            fn fetch_account(
                &self,
                state_root: &[u8; 32],
                address: [u8; 20],
            ) -> Result<Option<OracleAccount>, crate::oracle::OracleError> {
                Err(crate::oracle::OracleError::StateUnavailable {
                    state_root: *state_root,
                    address,
                    slot: None,
                })
            }
            fn fetch_storage(
                &self,
                _: &[u8; 32],
                _: [u8; 20],
                _: U256,
            ) -> Result<U256, crate::oracle::OracleError> {
                unreachable!("short-circuit only fetches the account")
            }
            fn fetch_bytecode(&self, _: &[u8; 32]) -> Result<Vec<u8>, crate::oracle::OracleError> {
                unreachable!("short-circuit only fetches the account")
            }
        }
        let exec = EvmExecutor::new(
            Arc::new(FailingOracle),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let got = exec.estimate_gas(
            [0x42; 20], TARGET, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1),
        );
        assert!(got.is_err(), "state-unavailable must be an error, got {got:?}");
    }

    #[test]
    fn calldata_to_codeless_account_skips_the_short_circuit() {
        // Non-empty calldata must NOT short-circuit (EIP-7623 floor + intrinsic
        // calldata gas apply) — the estimate is buffered and above 21000.
        let fx = FixtureSnapStateOracle::new().with_account(
            ROOT,
            TARGET,
            OracleAccount {
                nonce: 1,
                balance: U256::ZERO,
                code_hash: myotis_core::trie::EMPTY_CODE_HASH,
                storage_root: [0x9; 32],
            },
        );
        let exec = EvmExecutor::new(
            Arc::new(fx),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let est = exec
            .estimate_gas([0x42; 20], TARGET, &[0xFFu8; 8], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert!(est > 21_000, "calldata must not short-circuit, was {est}");
    }

    #[test]
    fn estimate_gas_applies_the_buffer_over_intrinsic() {
        // A STOP contract does no EVM work, so gross gas ≈ the 21000 intrinsic (empty
        // calldata). The estimate is ceil(21000 * 1.15) = 24150, plus at most a small
        // cold-access charge — bounded well below a real-work call.
        let exec = executor_with(vec![0x00u8], None); // STOP
        let est = exec
            .estimate_gas([0x42; 20], TARGET, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert!(est >= 24_150, "estimate must apply the 1.15 buffer over intrinsic, was {est}");
        assert!(est < 30_000, "a STOP contract shouldn't estimate real-work gas, was {est}");
    }

    #[test]
    fn estimate_gas_reflects_evm_work() {
        // A contract that SSTOREs must estimate strictly more than a no-op STOP —
        // proving execution gas (not just intrinsic) is metered.
        let stop = executor_with(vec![0x00u8], None);
        let stop_est = stop
            .estimate_gas([0x42; 20], TARGET, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        // PUSH1 0x2a PUSH1 0x00 SSTORE STOP — a fresh (0→nonzero) storage write.
        let sstore = executor_with(vec![0x60u8, 0x2a, 0x60, 0x00, 0x55, 0x00], None);
        let sstore_est = sstore
            .estimate_gas([0x42; 20], TARGET, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert!(sstore_est > stop_est, "SSTORE={sstore_est} must exceed STOP={stop_est}");
    }

    #[test]
    fn estimate_gas_covers_the_eip7623_calldata_floor() {
        use crate::fork::PRAGUE_TIME;
        // A STOP contract ignores calldata, but on Prague+ EIP-7623 charges a floor of
        // 21000 + 10*(zero + 4*nonzero) tokens. 200 nonzero bytes → floor 21000 +
        // 10*800 = 29000, ABOVE the standard intrinsic (21000 + 16*200 = 24200) — so
        // the estimate must reflect the FLOOR, or a real tx would be rejected below it.
        let exec = executor_with(vec![0x00u8], None); // STOP
        let calldata = vec![0x11u8; 200]; // 200 nonzero bytes
        let est = exec
            .estimate_gas([0x42; 20], TARGET, &calldata, U256::ZERO, &ctx(23_000_000, PRAGUE_TIME + 1))
            .unwrap();
        // floor = 29000; ceil(29000 * 1.15) = 33350.
        assert!(est >= 33_350, "estimate must cover the EIP-7623 calldata floor, was {est}");
    }

    #[test]
    fn estimate_gas_reverts_yield_no_number() {
        // PUSH1 0xAB PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 REVERT — a revert has no estimate.
        let code = vec![0x60u8, 0xAB, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xfd];
        let exec = executor_with(code, None);
        let err = exec
            .estimate_gas([0x42; 20], TARGET, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap_err();
        assert!(matches!(err, EvmError::Reverted { .. }), "got {err:?}");
    }

    #[test]
    fn non_mainnet_chain_is_rejected() {
        let code = vec![
            0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let exec = executor_with(code, None);
        let mut c = ctx(19_500_000, CANCUN_TIME + 1);
        c.chain_id = 137; // Polygon — no fork table here, spec_for must fail closed
        let err = exec.call_view(TARGET, &[], &c).unwrap_err();
        assert!(
            matches!(err, EvmError::UnsupportedChain { chain_id: 137 }),
            "got {err:?}"
        );
    }

    #[test]
    fn sepolia_context_executes_with_its_chain_id() {
        // Regression (found live): build_fill() defaults tx.chain_id to mainnet's
        // Some(1); without the explicit override every call on a non-mainnet chain
        // fails revm's chain-id validation ("invalid chain ID"). CHAINID opcode:
        // PUSH result of chainid, MSTORE, RETURN 32 bytes.
        let code = vec![0x46u8, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, None);
        let mut c = ctx(9_000_000, crate::fork::SEPOLIA_PRAGUE_TIME + 1);
        c.chain_id = 11_155_111;
        let out = exec.call_view(TARGET, &[], &c).expect("sepolia call must run");
        assert_eq!(U256::from_be_slice(&out), U256::from(11_155_111u64));
    }

    #[test]
    fn pre_london_block_is_fork_too_old() {
        let code = vec![
            0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let exec = executor_with(code, None);
        // Below London and no post-merge timestamp → rejected before any execution.
        let err = exec
            .call_view(TARGET, &[], &ctx(LONDON_BLOCK - 1, 0))
            .unwrap_err();
        assert!(matches!(err, EvmError::ForkTooOld { .. }), "got {err:?}");
    }

    #[test]
    fn absent_target_returns_empty_output() {
        // Empty fixture: the target account is absent → calling it returns empty
        // (no code to run), which revm treats as an immediate success with empty
        // output. A *state-unavailable* oracle would instead surface EvmError::Oracle;
        // here we assert the absent-account path returns empty, not a panic.
        let exec = EvmExecutor::new(
            Arc::new(FixtureSnapStateOracle::new()),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let out = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert!(out.is_empty());
    }
}
