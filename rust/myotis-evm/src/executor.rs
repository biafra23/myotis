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
use crate::database::{AccessSet, OracleDatabase};
use crate::error::EvmError;
use crate::fork::spec_for;
use crate::oracle::{OracleError, SnapStateOracle};
use crate::overrides::StateOverrides;

/// The gas a view call is given — the mainnet block gas limit. Also set as the
/// per-tx gas cap so revm's spec-default cap (2²⁴ on the latest fork, EIP-7825)
/// doesn't clip an `eth_call` that legitimately wants the full block budget.
pub const VIEW_CALL_GAS: u64 = 30_000_000;

/// Speculative-prefetch convergence cap (Java `DEFAULT_ITERATION_CAP` — plan-
/// mandated 4): at most two sentinel discovery passes, then real runs; a call
/// still discovering at the cap fails closed.
const PREFETCH_ITERATION_CAP: usize = 4;

/// Interpret a converged real run for the call path.
fn finish_call(result: ExecutionResult) -> Result<Vec<u8>, EvmError> {
    match result {
        ExecutionResult::Success { output, .. } => Ok(output_bytes(output)),
        ExecutionResult::Revert { output, .. } => Err(EvmError::Reverted { data: output.to_vec() }),
        ExecutionResult::Halt { reason, .. } => Err(map_halt(reason)),
    }
}

/// The exact intrinsic cost of a plain value transfer — the empty-calldata
/// no-code estimate short-circuit's answer (unbuffered; Java parity).
const PLAIN_TRANSFER_GAS: u64 = 21_000;

/// Precompiles are CODELESS in state yet execute logic — an empty-calldata
/// call to one still charges its base gas, so the 21000 short-circuit must
/// not claim it. Conservatively covers 0x…0001 ..= 0x…01ff (mainnet uses
/// 0x01..0x11 through Prague, 0x100 = P256VERIFY since Osaka; the headroom
/// absorbs future assignments — a stray fall-through only costs a full
/// estimate run). NOTE: the Java engine's rpcEstimateGas short-circuits these
/// today (same under-estimate) — flagged for the same fix there.
fn in_precompile_range(addr: &[u8; 20]) -> bool {
    addr[..18].iter().all(|&b| b == 0) && {
        let low = u16::from_be_bytes([addr[18], addr[19]]);
        (1..=0x01FF).contains(&low)
    }
}

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

    /// [`Self::call_view_from`] with caller-supplied [`StateOverrides`] layered
    /// over the verified state for this call only.
    ///
    /// The result is NOT a chain fact — it answers "what would this return if
    /// these accounts looked like this", which is what the caller asked. The
    /// override never reaches the proof or bytecode caches, so it cannot affect
    /// any other call (see [`crate::overrides`]).
    pub fn call_view_overridden(
        &self,
        sender: [u8; 20],
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
        overrides: StateOverrides,
    ) -> Result<Vec<u8>, EvmError> {
        self.call_capped_with(
            Address::from(sender),
            Some(target),
            calldata,
            value,
            ctx,
            PREFETCH_ITERATION_CAP,
            overrides,
        )
    }

    /// `eth_call` with NO `to` — contract creation. The init code runs and its
    /// return data is the answer, exactly as geth answers a `to`-less call.
    ///
    /// This is the second way wallets run a helper contract they never deploy
    /// (Ambire's deployless `Deploy` mode; the first is a state override). A
    /// node that serves only one of the two forces the wallet's build-time
    /// choice to match, which is not a choice we should be making for it.
    pub fn create_view(
        &self,
        sender: [u8; 20],
        init_code: &[u8],
        value: U256,
        ctx: &BlockContext,
        overrides: StateOverrides,
    ) -> Result<Vec<u8>, EvmError> {
        self.call_capped_with(
            Address::from(sender),
            None,
            init_code,
            value,
            ctx,
            PREFETCH_ITERATION_CAP,
            overrides,
        )
    }

    /// `estimateGas` for a call (`to` != null): run it and return the gas LIMIT that
    /// would let it succeed. Reverts/halts yield no
    /// number (an `Err`); a revert's typed payload survives to the host, which
    /// serves it as the standard JSON-RPC code-3 `execution reverted` error —
    /// halts stay the retryable null.
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
        target: Option<[u8; 20]>,
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
        let db = self.database_for(ctx);
        self.execute_with_db(&db, spec, caller, target, calldata, value, ctx)
    }

    fn database_for(&self, ctx: &BlockContext) -> OracleDatabase {
        self.database_for_with(ctx, StateOverrides::new())
    }

    fn database_for_with(&self, ctx: &BlockContext, overrides: StateOverrides) -> OracleDatabase {
        OracleDatabase::with_overrides(
            Arc::clone(&self.oracle),
            ctx.state_root,
            Arc::clone(&self.proof_cache),
            Arc::clone(&self.bytecode_cache),
            overrides,
        )
    }

    /// One `transact` against a caller-owned database (the convergence loop
    /// shares ONE database — and thus one per-call view cache — across all of
    /// its iterations, so fetched state carries forward).
    #[allow(clippy::too_many_arguments)]
    fn execute_with_db(
        &self,
        db: &OracleDatabase,
        spec: revm::primitives::hardfork::SpecId,
        caller: Address,
        target: Option<[u8; 20]>,
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<ExecutionResult, EvmError> {
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
            // `None` ⇒ CONTRACT CREATION: `eth_call` with no `to`, where the
            // "constructor" runs and its RETURN DATA is the answer. Wallets use
            // this to run a helper contract they never deploy (Ambire's
            // deployless Deploy mode), which is the same job as a state
            // override by another route.
            .kind(match target {
                Some(to) => TxKind::Call(Address::from(to)),
                None => TxKind::Create,
            })
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

    /// Run a call and return its output bytes (revert/halt → `Err`), via the
    /// speculative prefetch CONVERGENCE LOOP (the Java `PrefetchingEvmExecutor.
    /// runConvergent` twin): sentinel discovery passes hand out zero-shaped
    /// placeholders for network misses while recording every access; each pass
    /// discovers one data-dependency hop, whose fresh accesses are batch-warmed
    /// in one parallel wave; the last two iterations always run REAL. Fails
    /// closed with [`EvmError::IterationLimitExceeded`] at the cap.
    fn call(
        &self,
        caller: Address,
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<Vec<u8>, EvmError> {
        self.call_capped(caller, target, calldata, value, ctx, PREFETCH_ITERATION_CAP)
    }

    /// [`Self::call`] with an explicit iteration cap (tests pin the fail-closed
    /// cap behavior with cap=1, mirroring Java's `iterationCapOfOneAlwaysExceeds`).
    #[allow(clippy::too_many_arguments)]
    fn call_capped(
        &self,
        caller: Address,
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
        cap: usize,
    ) -> Result<Vec<u8>, EvmError> {
        self.call_capped_with(caller, Some(target), calldata, value, ctx, cap, StateOverrides::new())
    }

    #[allow(clippy::too_many_arguments)]
    fn call_capped_with(
        &self,
        caller: Address,
        target: Option<[u8; 20]>,
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
        cap: usize,
        overrides: StateOverrides,
    ) -> Result<Vec<u8>, EvmError> {
        let spec = spec_for(ctx.chain_id, ctx.block_number, ctx.timestamp)?;
        let db = self.database_for_with(ctx, overrides);

        // Prime the target's account + code synchronously (sentinel OFF, not
        // access-tracked — Java parity) so iteration 0 executes real top-level
        // code instead of a sentinel empty account.
        // A create has no target account to prime; its code is the calldata.
        if let Some(to) = target {
            if let Some(acc) = db.basic_ref(Address::from(to))? {
                db.code_by_hash_ref(acc.code_hash)?;
            }
        }
        let _ = db.take_access_set(); // the prime is not part of any snapshot

        let mut seen = AccessSet::default();
        let mut discovering = true;
        for iter in 0..cap {
            // Sentinel while still discovering, but the LAST TWO iterations are
            // always real (one final wave + one warm real run).
            let sentinel = discovering && iter + 2 < cap;
            db.set_sentinel(sentinel);
            let misses_before = db.sentinel_misses();
            let outcome = self.execute_with_db(&db, spec, caller, target, calldata, value, ctx);
            db.set_sentinel(false);
            let fresh = db.take_access_set().minus(&seen);

            if sentinel {
                // A sentinel run that discovered nothing new AND handed out no
                // placeholder was all verified hits — byte-identical to a real
                // run: return it (the hit-only fast path). A sentinel failure
                // (zeroes tripping a require()) is tolerated; its partial
                // access set still drives the wave.
                //
                // Two deliberate deviations from Java here: (1) the access diff
                // includes CODE hashes (Java diffs only accounts+slots) — a
                // code-only discovery keeps the wave warm instead of going
                // serial, and determinism over verified state still guarantees
                // convergence; (2) a hit-only run's REVERT returns immediately
                // (Java re-derives the identical revert from the next real run
                // — all-verified reads make the outcome deterministic, so this
                // is the same answer one iteration sooner).
                if fresh.is_empty() {
                    if db.sentinel_misses() == misses_before {
                        if let Ok(result) = outcome {
                            return finish_call(result);
                        }
                    }
                    discovering = false;
                } else {
                    self.prefetch_wave(ctx, &fresh);
                    seen.merge(fresh);
                }
            } else {
                // Real-run outcomes are authoritative: errors (incl. reverts —
                // they ARE the answer, callers key on the revert data) propagate.
                let result = outcome?;
                if fresh.is_empty() {
                    return finish_call(result); // converged
                }
                // Still discovering under real mode (a sentinel zero had hidden
                // a branch): warm the stragglers and run again.
                self.prefetch_wave(ctx, &fresh);
                seen.merge(fresh);
            }
        }
        Err(EvmError::IterationLimitExceeded { cap })
    }

    /// One best-effort parallel warm-up wave over freshly-discovered accesses:
    /// slots grouped per account + the touched accounts + code hashes, handed to
    /// the oracle's batch primitive (concurrent per-peer fan-out on the network
    /// oracle; no-op on fixtures).
    fn prefetch_wave(&self, ctx: &BlockContext, fresh: &AccessSet) {
        let mut by_account: std::collections::HashMap<[u8; 20], Vec<U256>> =
            std::collections::HashMap::new();
        for addr in &fresh.accounts {
            by_account.entry(*addr).or_default();
        }
        for (addr, slot) in &fresh.slots {
            by_account.entry(*addr).or_default().push(*slot);
        }
        let items: Vec<([u8; 20], Vec<U256>)> = by_account.into_iter().collect();
        let code_hashes: Vec<[u8; 32]> = fresh.code_hashes.iter().copied().collect();
        self.oracle.prefetch_batch(
            &ctx.state_root,
            &items,
            &code_hashes,
            &*self.proof_cache,
            &*self.bytecode_cache,
        );
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
        if calldata.is_empty() && !in_precompile_range(&target) {
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
        match self.execute(caller, Some(target), calldata, value, ctx)? {
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

    /// THE wallet pattern this exists for (#314): Ambire/Kohaku reads account
    /// state by calling a magic address that has NO on-chain account and
    /// supplying the helper's bytecode as an override. Ignoring the override
    /// returns empty output — a well-formed answer to a different question.
    #[test]
    fn deployless_call_runs_overridden_code_at_an_account_that_does_not_exist() {
        use crate::overrides::{AccountOverride, StateOverrides};
        const MAGIC: [u8; 20] = [0x69; 20];
        // PUSH1 0x2a; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN  -> returns 42
        let code = vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        // Fixture has NOTHING at MAGIC: the account exists only as a hypothesis.
        let ex = EvmExecutor::new(
            Arc::new(FixtureSnapStateOracle::new()),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let c = ctx(LONDON_BLOCK, CANCUN_TIME);

        // Without the override there is no code to run: empty output.
        let bare = ex.call_view(MAGIC, &[], &c).expect("call runs");
        assert!(bare.is_empty(), "expected empty output without an override, got {bare:?}");

        // With it, the injected code executes.
        let mut ov = StateOverrides::new();
        ov.insert(MAGIC, AccountOverride { code: Some(code), ..Default::default() });
        let out = ex
            .call_view_overridden(VIEW_CALLER.into_array(), MAGIC, &[], U256::ZERO, &c, ov)
            .expect("overridden call runs");
        assert_eq!(U256::from_be_slice(&out), U256::from(42));
    }

    #[test]
    fn storage_and_balance_overrides_apply_and_do_not_leak() {
        use crate::overrides::{AccountOverride, StateOverrides};
        // SLOAD slot 0 and return it.
        let code = vec![0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let ex = executor_with(code, Some(U256::from(7)));
        let c = ctx(LONDON_BLOCK, CANCUN_TIME);

        // Verified state says 7.
        assert_eq!(U256::from_be_slice(&ex.call_view(TARGET, &[], &c).unwrap()), U256::from(7));

        // stateDiff overlays just that slot.
        let mut over = AccountOverride::default();
        over.state_diff.insert(U256::ZERO, U256::from(99));
        let mut ov = StateOverrides::new();
        ov.insert(TARGET, over);
        let out = ex
            .call_view_overridden(VIEW_CALLER.into_array(), TARGET, &[], U256::ZERO, &c, ov)
            .unwrap();
        assert_eq!(U256::from_be_slice(&out), U256::from(99));

        // The override must not have leaked into any cache: the next ordinary
        // call sees verified state again. This is the trust-critical property —
        // a hypothesis must not become a "fact" for later calls.
        assert_eq!(U256::from_be_slice(&ex.call_view(TARGET, &[], &c).unwrap()), U256::from(7));
    }

    /// THE OTHER deployless form (#314 follow-up): `eth_call` with NO `to`,
    /// where init code runs and its RETURN DATA is the answer. Ambire picks this
    /// mode whenever a network is flagged `rpcNoStateOverride`, so a node that
    /// serves only the override form leaves those wallets broken.
    #[test]
    fn contract_creation_call_returns_the_constructor_output() {
        use crate::overrides::StateOverrides;
        // Init code that returns 42 as its "deployed code" — exactly the shape a
        // deployless helper uses to hand back an ABI result.
        // PUSH1 0x2a; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
        let init = vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let ex = EvmExecutor::new(
            Arc::new(FixtureSnapStateOracle::new()),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let out = ex
            .create_view([0u8; 20], &init, U256::ZERO, &ctx(LONDON_BLOCK, CANCUN_TIME), StateOverrides::new())
            .expect("creation call runs");
        assert_eq!(U256::from_be_slice(&out), U256::from(42));
    }

    #[test]
    fn contract_creation_call_sees_overrides_too() {
        // The two deployless modes are interchangeable to the caller, so the
        // create form must honour overrides as well — e.g. init code that reads
        // another account's storage.
        use crate::overrides::{AccountOverride, StateOverrides};
        const OTHER: [u8; 20] = [0x77; 20];
        // PUSH20 OTHER; EXTCODESIZE; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
        let mut init = vec![0x73];
        init.extend_from_slice(&OTHER);
        init.extend_from_slice(&[0x3b, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
        let ex = EvmExecutor::new(
            Arc::new(FixtureSnapStateOracle::new()),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let c = ctx(LONDON_BLOCK, CANCUN_TIME);
        // No override: the account has no code, so size 0.
        let bare = ex.create_view([0u8; 20], &init, U256::ZERO, &c, StateOverrides::new()).unwrap();
        assert_eq!(U256::from_be_slice(&bare), U256::ZERO);
        // With one: the injected code's length.
        let mut ov = StateOverrides::new();
        ov.insert(OTHER, AccountOverride { code: Some(vec![0x00; 5]), ..Default::default() });
        let with = ex.create_view([0u8; 20], &init, U256::ZERO, &c, ov).unwrap();
        assert_eq!(U256::from_be_slice(&with), U256::from(5));
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
    fn precompile_target_is_never_short_circuited() {
        // Precompiles are codeless in state but still execute: the identity
        // precompile (0x04) with empty calldata costs 21000 + its base gas, so
        // answering a bare 21000 would under-estimate. The guard forces the
        // full metered path (which prices the precompile via revm).
        let mut precompile = [0u8; 20];
        precompile[19] = 0x04;
        let fx = FixtureSnapStateOracle::new(); // absent everywhere, like real state
        let exec = EvmExecutor::new(
            Arc::new(fx),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let est = exec
            .estimate_gas([0x42; 20], precompile, &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert!(est > 21_000, "a precompile call must be metered, was {est}");
        // The zero address is NOT a precompile — burns short-circuit normally.
        let est0 = exec
            .estimate_gas([0x42; 20], [0u8; 20], &[], U256::ZERO, &ctx(19_500_000, CANCUN_TIME + 1))
            .unwrap();
        assert_eq!(est0, 21_000);
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
    fn prefetched_and_direct_agree() {
        // The Java prefetchedAndDirectAgree differential: the convergence loop
        // and a direct single execution must return byte-identical results —
        // the no-sentinel-leak invariant, pinned end-to-end.
        let code = vec![0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, Some(U256::from(1234u64)));
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let looped = exec.call_view(TARGET, &[], &c).unwrap();
        let direct = {
            let spec = spec_for(c.chain_id, c.block_number, c.timestamp).unwrap();
            let db = exec.database_for(&c);
            match exec
                .execute_with_db(&db, spec, Address::from([0u8; 20]), Some(TARGET), &[], U256::ZERO, &c)
                .unwrap()
            {
                ExecutionResult::Success { output, .. } => output_bytes(output),
                other => panic!("direct run must succeed, got {other:?}"),
            }
        };
        assert_eq!(looped, direct);
    }

    #[test]
    fn warm_cache_converges_with_zero_oracle_fetches() {
        // Hit-only fast path: with REAL shared caches warmed by a first call,
        // the second identical call must touch the oracle ZERO times.
        #[derive(Default)]
        struct Counting {
            inner: FixtureSnapStateOracle,
            fetches: std::sync::atomic::AtomicUsize,
        }
        impl crate::oracle::SnapStateOracle for Counting {
            fn fetch_account(
                &self, r: &[u8; 32], a: [u8; 20],
            ) -> Result<Option<OracleAccount>, crate::oracle::OracleError> {
                self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.inner.fetch_account(r, a)
            }
            fn fetch_storage(
                &self, r: &[u8; 32], a: [u8; 20], s: U256,
            ) -> Result<U256, crate::oracle::OracleError> {
                self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.inner.fetch_storage(r, a, s)
            }
            fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, crate::oracle::OracleError> {
                self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.inner.fetch_bytecode(h)
            }
        }
        let code = vec![0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let ch = keccak256(&code);
        let mut fx = FixtureSnapStateOracle::new().with_account(
            ROOT, TARGET,
            OracleAccount { nonce: 1, balance: U256::ZERO, code_hash: ch, storage_root: [0x9; 32] },
        );
        assert_eq!(fx.with_bytecode(code), ch);
        let fx = fx.with_storage(ROOT, TARGET, [0u8; 32], U256::from(7u64));
        let oracle = Arc::new(Counting { inner: fx, fetches: Default::default() });
        let exec = EvmExecutor::new(
            Arc::clone(&oracle) as Arc<dyn crate::oracle::SnapStateOracle>,
            Arc::new(crate::cache::InMemoryStateProofCache::new(1024)),
            Arc::new(crate::cache::InMemoryBytecodeCache::default()),
        );
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        assert_eq!(
            U256::from_be_slice(&exec.call_view(TARGET, &[], &c).unwrap()),
            U256::from(7u64)
        );
        let after_first = oracle.fetches.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            U256::from_be_slice(&exec.call_view(TARGET, &[], &c).unwrap()),
            U256::from(7u64)
        );
        let after_second = oracle.fetches.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(after_first, after_second, "warm second call must not touch the oracle");
    }

    #[test]
    fn two_hop_dependency_converges_with_two_waves() {
        // slot0 holds K; the contract then SLOADs K — the loop's raison d'être:
        // hop 1 discovers slot0, hop 2 discovers slot K, two waves, converge.
        // PUSH1 0 SLOAD SLOAD PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
        #[derive(Default)]
        struct Recording {
            inner: FixtureSnapStateOracle,
            waves: std::sync::Mutex<Vec<Vec<([u8; 20], Vec<U256>)>>>,
        }
        impl crate::oracle::SnapStateOracle for Recording {
            fn fetch_account(
                &self, r: &[u8; 32], a: [u8; 20],
            ) -> Result<Option<OracleAccount>, crate::oracle::OracleError> {
                self.inner.fetch_account(r, a)
            }
            fn fetch_storage(
                &self, r: &[u8; 32], a: [u8; 20], s: U256,
            ) -> Result<U256, crate::oracle::OracleError> {
                self.inner.fetch_storage(r, a, s)
            }
            fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, crate::oracle::OracleError> {
                self.inner.fetch_bytecode(h)
            }
            fn prefetch_batch(
                &self,
                _root: &[u8; 32],
                accounts: &[([u8; 20], Vec<U256>)],
                _code: &[[u8; 32]],
                _ps: &dyn crate::cache::StateProofCache,
                _cs: &dyn crate::cache::BytecodeCache,
            ) {
                self.waves.lock().unwrap().push(accounts.to_vec());
            }
        }
        let code = vec![0x60u8, 0x00, 0x54, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let ch = keccak256(&code);
        let mut fx = FixtureSnapStateOracle::new().with_account(
            ROOT, TARGET,
            OracleAccount { nonce: 1, balance: U256::ZERO, code_hash: ch, storage_root: [0x9; 32] },
        );
        assert_eq!(fx.with_bytecode(code), ch);
        let mut k = [0u8; 32];
        k[31] = 5;
        let fx = fx
            .with_storage(ROOT, TARGET, [0u8; 32], U256::from(5u64)) // slot0 → K=5
            .with_storage(ROOT, TARGET, k, U256::from(42u64)); // slot5 → 42
        let rec = Arc::new(Recording { inner: fx, waves: Default::default() });
        let exec = EvmExecutor::new(
            Arc::clone(&rec) as Arc<dyn crate::oracle::SnapStateOracle>,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let out = exec.call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1)).unwrap();
        assert_eq!(U256::from_be_slice(&out), U256::from(42u64));
        let waves = rec.waves.lock().unwrap();
        assert!(waves.len() >= 2, "two dependency hops need two waves, got {}", waves.len());
        let slot_in = |w: &Vec<([u8; 20], Vec<U256>)>, s: U256| {
            w.iter().any(|(a, slots)| *a == TARGET && slots.contains(&s))
        };
        assert!(slot_in(&waves[0], U256::ZERO), "hop 1 discovers slot 0");
        assert!(slot_in(&waves[1], U256::from(5u64)), "hop 2 discovers slot K");
    }

    #[test]
    fn iteration_cap_of_one_always_exceeds() {
        // Java iterationCapOfOneAlwaysExceeds twin: any state-reading call needs
        // ≥2 iterations to converge (discover, then confirm), so cap=1 must fail
        // CLOSED — never answer from a run that was still discovering.
        let code = vec![0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, Some(U256::from(7u64)));
        let got = exec.call_capped(
            Address::from([0u8; 20]), TARGET, &[], U256::ZERO,
            &ctx(19_500_000, CANCUN_TIME + 1), 1,
        );
        assert!(
            matches!(got, Err(EvmError::IterationLimitExceeded { cap: 1 })),
            "cap=1 must fail closed, got {got:?}"
        );
    }

    #[test]
    fn sentinel_revert_is_tolerated_and_real_run_answers() {
        // The contract REVERTs when slot0 == 0 — exactly what the sentinel pass
        // sees (placeholder zero). The revert must be swallowed, the discovered
        // slot warmed, and the REAL run (slot0 = 7) return successfully.
        // PUSH1 0 SLOAD PUSH1 0x0b JUMPI PUSH1 0 PUSH1 0 REVERT JUMPDEST
        // PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
        let code = vec![
            0x60u8, 0x00, 0x54, 0x60, 0x0b, 0x57, 0x60, 0x00, 0x60, 0x00, 0xfd, 0x5b,
            0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let exec = executor_with(code, Some(U256::from(7u64)));
        let out = exec
            .call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1))
            .expect("sentinel revert must not surface; the real run answers");
        assert_eq!(U256::from_be_slice(&out), U256::from(7u64));
    }

    #[test]
    fn prefetch_wave_carries_the_discovered_slot() {
        // A recording oracle: the wave must fire with the SLOAD-discovered slot
        // grouped under the target account.
        #[derive(Default)]
        struct Recording {
            inner: FixtureSnapStateOracle,
            waves: std::sync::Mutex<Vec<Vec<([u8; 20], Vec<U256>)>>>,
        }
        impl crate::oracle::SnapStateOracle for Recording {
            fn fetch_account(
                &self, r: &[u8; 32], a: [u8; 20],
            ) -> Result<Option<OracleAccount>, crate::oracle::OracleError> {
                self.inner.fetch_account(r, a)
            }
            fn fetch_storage(
                &self, r: &[u8; 32], a: [u8; 20], s: U256,
            ) -> Result<U256, crate::oracle::OracleError> {
                self.inner.fetch_storage(r, a, s)
            }
            fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, crate::oracle::OracleError> {
                self.inner.fetch_bytecode(h)
            }
            fn prefetch_batch(
                &self,
                _root: &[u8; 32],
                accounts: &[([u8; 20], Vec<U256>)],
                _code: &[[u8; 32]],
                _ps: &dyn crate::cache::StateProofCache,
                _cs: &dyn crate::cache::BytecodeCache,
            ) {
                self.waves.lock().unwrap().push(accounts.to_vec());
            }
        }
        let code = vec![0x60u8, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let ch = keccak256(&code);
        let mut fx = FixtureSnapStateOracle::new().with_account(
            ROOT, TARGET,
            OracleAccount { nonce: 1, balance: U256::ZERO, code_hash: ch, storage_root: [0x9; 32] },
        );
        assert_eq!(fx.with_bytecode(code), ch);
        let fx = fx.with_storage(ROOT, TARGET, [0u8; 32], U256::from(7u64));
        let rec = Arc::new(Recording { inner: fx, waves: std::sync::Mutex::new(Vec::new()) });
        let exec = EvmExecutor::new(
            Arc::clone(&rec) as Arc<dyn crate::oracle::SnapStateOracle>,
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let out = exec.call_view(TARGET, &[], &ctx(19_500_000, CANCUN_TIME + 1)).unwrap();
        assert_eq!(U256::from_be_slice(&out), U256::from(7u64));
        let waves = rec.waves.lock().unwrap();
        assert!(!waves.is_empty(), "the sentinel pass must trigger a wave");
        let first = &waves[0];
        let target_item = first.iter().find(|(a, _)| *a == TARGET).expect("target in wave");
        assert!(target_item.1.contains(&U256::ZERO), "slot 0 must ride the wave");
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
