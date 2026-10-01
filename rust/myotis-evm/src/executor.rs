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

use revm::context::result::{ExecutionResult, HaltReason, InvalidTransaction, Output};
use revm::context::{CfgEnv, TxEnv};
use revm::context_interface::transaction::{
    AccessList, AccessListItem as RevmAccessListItem, Authorization as RevmAuthorization,
    SignedAuthorization,
};
use revm::database_interface::{DBErrorMarker, DatabaseRef};
use revm::primitives::eip7825::TX_GAS_LIMIT_CAP;
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address, Bytes, TxKind, B256, U256};
use revm::{Context, InspectEvm, Inspector, MainBuilder, MainContext};
use revm::interpreter::{Interpreter, InterpreterAction, InterpreterResult, InstructionResult};
use revm::interpreter::interpreter_types::LoopControl;

struct RequestInspector<'a>(&'a dyn SnapStateOracle);
impl<CTX> Inspector<CTX> for RequestInspector<'_> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        if self.0.check_request().is_err() {
            interp.bytecode.set_action(InterpreterAction::Return(InterpreterResult {
                result: InstructionResult::Stop,
                output: Default::default(),
                gas: interp.gas,
            }));
        }
    }
}

use crate::block::BlockContext;
use crate::cache::{BytecodeCache, StateProofCache};
use crate::database::{AccessSet, OracleDatabase};
use crate::error::EvmError;
use crate::fork::spec_for;
use crate::oracle::{OracleError, SnapStateOracle};
use crate::overrides::StateOverrides;
use crate::tx::{Fees, TxRequest, TYPE_DYNAMIC_FEE, TYPE_SET_CODE};

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
/// no-code estimate short-circuit's answer (unbuffered; Java parity). Exact only
/// before Amsterdam (EIP-2780), so the short-circuit stops at that fork.
const PLAIN_TRANSFER_GAS: u64 = 21_000;

/// The gas a value-bearing CALL hands its callee on top (`params.CallStipend`):
/// geth's first probe adds it to what the run drew.
const CALL_STIPEND: u64 = 2_300;

/// How close to the lowest working limit the estimate's search stops, as
/// `(numerator, denominator)`: geth's `estimateGasErrorRatio`, 1.5%. The 1.15
/// buffer on top dwarfs it.
const ESTIMATE_ERROR_RATIO: (u128, u128) = (15, 1_000);

/// Precompiles are CODELESS in state yet execute logic — an empty-calldata
/// call to one still charges its base gas, so the 21000 short-circuit must
/// not claim it. Conservatively covers 0x…0001 ..= 0x…01ff (mainnet uses
/// 0x01..0x11 through Prague, 0x100 = P256VERIFY since Osaka; the headroom
/// absorbs future assignments — a stray fall-through only costs a full
/// estimate run). The Java backend's short-circuit guards the same range
/// (`VerifiedRpcBackend.inPrecompileRange`).
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

    /// `estimateGas` for a call (`to` != null) carrying only `from`/`to`/`data`/
    /// `value`: [`Self::estimate_tx`] with every other field absent.
    pub fn estimate_gas(
        &self,
        from: [u8; 20],
        target: [u8; 20],
        calldata: &[u8],
        value: U256,
        ctx: &BlockContext,
    ) -> Result<u64, EvmError> {
        let tx = TxRequest::call(from, Some(target), Bytes::copy_from_slice(calldata), value);
        self.estimate_tx(&tx, ctx, StateOverrides::new())
    }

    /// `eth_estimateGas` for a full transaction object (#509): run it and return
    /// the gas LIMIT that lets it succeed. Every field the request names is
    /// applied — authorization list, access list, gas, fees, nonce, type; see
    /// [`crate::tx`] — or the request is refused ([`EvmError::InvalidRequest`]),
    /// and `overrides` are layered over verified state for this run only.
    ///
    /// The answer never exceeds the ceiling the caller allowed (its `gas` —
    /// without one, the block's gas limit — what its fee cap can pay for, and
    /// [`VIEW_CALL_GAS`]); a transaction that does not succeed within it is
    /// [`EvmError::GasAllowanceExceeded`], geth's answer. A revert yields no
    /// number either: its typed payload survives to the host, which serves it
    /// as the standard JSON-RPC code-3 error.
    ///
    /// The number is geth's search for the lowest gas limit at which the
    /// transaction succeeds ([`Self::lowest_working_limit`]) with the 1.15
    /// buffer on top: a single run's gas draw is not a limit that works when
    /// a nested call withholds 1/64 of its gas at every level or a contract
    /// checks `gasleft()`.
    pub fn estimate_tx(
        &self,
        tx: &TxRequest,
        ctx: &BlockContext,
        overrides: StateOverrides,
    ) -> Result<u64, EvmError> {
        self.oracle.check_request()?;
        // Fork/chain validation FIRST, as on every entry point: an unsupported
        // chain or too-old fork fails closed before anything is decided —
        // including the 21000 short-circuit below, which must never answer for
        // a context the executor wouldn't execute.
        let spec = spec_for_context(ctx)?;
        check_tx(tx, ctx, spec)?;
        let db = self.database_for_with(ctx, with_sender_nonce(overrides, tx)?);
        // The checks and the short-circuit below read the sender's balance and
        // the target's code, and the run reads both: one parallel wave.
        self.prefetch_wave(
            ctx,
            &AccessSet { accounts: std::iter::once(tx.from).chain(tx.to).collect(), ..Default::default() },
        );

        // The ceiling (geth's `hi`): the executor's budget, lowered by the
        // caller's `gas` — below 21000 geth reads it as no limit, and so do we;
        // without one, geth starts from the block's gas limit, since no block
        // holds more — and, under a fee cap, by what the sender can pay for.
        let mut hi = VIEW_CALL_GAS;
        match tx.gas.filter(|g| *g >= PLAIN_TRANSFER_GAS) {
            Some(gas) => hi = hi.min(gas),
            None if ctx.gas_limit > 0 => hi = hi.min(ctx.gas_limit),
            None => {}
        }
        // EIP-7825 (Osaka): no transaction may carry more than 2^24 gas, so an
        // answer above it is a limit the network rejects; geth caps `hi` the
        // same way. (Amsterdam's EIP-8037 state-gas reservoir lifts the cap on
        // the total limit — revm skips the check there too.)
        if spec.is_enabled_in(SpecId::OSAKA) && !spec.is_enabled_in(SpecId::AMSTERDAM) {
            hi = hi.min(TX_GAS_LIMIT_CAP);
        }
        let fee_cap = tx.fees.fee_cap();
        if fee_cap > 0 {
            // The sender's balance as the run will see it (overrides included).
            let balance = db.basic_ref(Address::from(tx.from))?.map_or(U256::ZERO, |a| a.balance);
            if tx.value >= balance {
                return Err(EvmError::InsufficientFundsForTransfer);
            }
            let fundable = (balance - tx.value) / U256::from(fee_cap);
            if fundable < U256::from(hi) {
                hi = fundable.to::<u64>();
            }
            // revm prices the run as `gas_limit × price` in u128 and `expect`s it
            // not to overflow — with its own balance check off, nothing else
            // stops a state-overridden balance above 2^128 from making it
            // (a panic, which aborts the host). Only an absurd fee cap reaches
            // this bound, and there it reads as the caller's allowance anyway.
            hi = hi.min(u64::try_from(u128::MAX / fee_cap).unwrap_or(u64::MAX));
        }
        // geth checks the fee cap against the base fee when it first RUNS the
        // transaction, so after the affordability checks above and before the
        // 21000 short-circuit below (which geth answers by running it too) —
        // and its estimator reports that run's refusal with the ceiling it ran at.
        check_fee_cap(tx, ctx).map_err(|error| EvmError::FailedWithGas { gas: hi, error: Box::new(error) })?;
        // Then its buyGas at the ceiling. Under a fee cap the ceiling already
        // fits the balance; without one geth still holds the sender to the value
        // it moves, and reports that run's refusal the same way.
        if let Some(short) = buy_gas_shortfall(&db, tx, hi)? {
            return Err(EvmError::FailedWithGas { gas: hi, error: Box::new(short) });
        }

        // Java `rpcEstimateGas` parity: a plain transfer (empty calldata) to a
        // CODELESS account costs exactly 21000 — no EVM run and NO 1.15 buffer
        // (it's exact). One verified account fetch through the caching database
        // decides it; an account WITH code (contract, or an EIP-7702-delegated
        // EOA) falls through to the full estimate, and so does a request whose
        // access or authorization list changes the price (geth runs such a
        // transfer rather than assume), or whose ceiling does not reach 21000.
        //
        // The flat 21000 is exact only BEFORE Amsterdam: EIP-2780 decomposes it
        // (sender base + recipient access + a value charge), and a value transfer
        // to an EMPTY account also pays EIP-8037 account-creation state gas — an
        // order of magnitude more than 21000. From AMSTERDAM the metered run below
        // prices it instead (buffered, like every metered estimate).
        if let Some(target) = tx.to {
            if tx.data.is_empty()
                && !tx.has_lists()
                && hi >= PLAIN_TRANSFER_GAS
                && !in_precompile_range(&target)
                && !spec.is_enabled_in(SpecId::AMSTERDAM)
            {
                let no_code = db
                    .basic_ref(Address::from(target))?
                    .is_none_or(|a| a.code_hash.0 == myotis_core::trie::EMPTY_CODE_HASH);
                if no_code {
                    self.oracle.check_request()?;
                    return Ok(PLAIN_TRANSFER_GAS);
                }
            }
        }
        let run = self.execute_with_db(&db, spec, tx, hi, ctx).map_err(|e| match e {
            // The intrinsic cost or the EIP-7623 floor above the ceiling: for an
            // estimate that is the caller's allowance talking, exactly like
            // running out of gas during execution — geth answers the same.
            EvmError::IntrinsicGasTooLow { .. } | EvmError::FloorDataGasTooLow { .. } => {
                EvmError::GasAllowanceExceeded { allowance: hi }
            }
            other => other,
        })?;
        match run {
            ExecutionResult::Success { gas, .. } => {
                // geth's search, from the most the run at the ceiling drew
                // (max(gross, floor), its `MaxUsedGas`). Never above the ceiling:
                // the run just succeeded AT it, so the ceiling is itself a limit
                // that works — geth's invariant.
                let drawn = gas.total_gas_spent().max(gas.tx_gas_used());
                let lowest = self.lowest_working_limit(&db, spec, tx, ctx, drawn, hi)?;
                Ok(with_estimate_buffer(lowest).min(hi))
            }
            ExecutionResult::Revert { output, .. } => {
                Err(EvmError::Reverted { data: output.to_vec() })
            }
            // Out of gas AT the ceiling: more than the caller allowed.
            ExecutionResult::Halt { reason: HaltReason::OutOfGas(_), .. } => {
                Err(EvmError::GasAllowanceExceeded { allowance: hi })
            }
            ExecutionResult::Halt { reason, .. } => Err(map_halt(reason)),
        }
    }

    /// geth's estimator search (`eth/gasestimator`) for the lowest gas limit
    /// at which `tx` succeeds, given a run at `hi` that succeeded having drawn
    /// `drawn`: a first probe tries what it drew plus the call stipend with
    /// the 63/64 a nested call withholds — usually the answer — and bisection,
    /// skewed low, stops within [`ESTIMATE_ERROR_RATIO`] of it. A probe that
    /// fails for any reason (out of gas, a revert, a halt, a limit below the
    /// intrinsic cost or the floor) raises the limit; an error reading state
    /// ends the search with it.
    ///
    /// One deliberate difference: geth searches down to what the run was
    /// charged (after refunds), where this search stops at what it drew. Below
    /// that a limit can only "work" by running a different transaction — a
    /// failure caught deep inside (try/catch, a multicall that tolerates one),
    /// a `gasleft()` branch — which is not the one the caller simulated.
    ///
    /// What that bound buys, exactly: a probe cannot tell a caught failure
    /// from success, so above the draw the search still finds the lowest limit
    /// at which the OUTER transaction succeeds. A call whose failure is caught
    /// d levels down needs (64/63)^d of what it drew; the 1.15 buffer covers
    /// that through d = 8, not from d = 9 on.
    fn lowest_working_limit(
        &self,
        db: &OracleDatabase,
        spec: SpecId,
        tx: &TxRequest,
        ctx: &BlockContext,
        drawn: u64,
        mut hi: u64,
    ) -> Result<u64, EvmError> {
        let mut lo = drawn.saturating_sub(1);
        let optimistic = (drawn + CALL_STIPEND) * 64 / 63;
        if optimistic < hi {
            if self.succeeds_with(db, spec, tx, ctx, optimistic)? {
                hi = optimistic;
            } else {
                lo = optimistic;
            }
        }
        while lo + 1 < hi {
            // Within the error ratio of the answer: a wallet bumps the limit
            // anyway, and every probe is a full run.
            let (num, den) = ESTIMATE_ERROR_RATIO;
            if u128::from(hi - lo) * den < u128::from(hi) * num {
                break;
            }
            // Skewed low: most transactions need little more than they drew.
            let mid = ((hi + lo) / 2).min(lo.saturating_mul(2));
            if self.succeeds_with(db, spec, tx, ctx, mid)? {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        Ok(hi)
    }

    /// Whether `tx` succeeds with `gas_limit` — one probe of
    /// [`Self::lowest_working_limit`].
    fn succeeds_with(
        &self,
        db: &OracleDatabase,
        spec: SpecId,
        tx: &TxRequest,
        ctx: &BlockContext,
        gas_limit: u64,
    ) -> Result<bool, EvmError> {
        match self.execute_with_db(db, spec, tx, gas_limit, ctx) {
            Ok(ExecutionResult::Success { .. }) => Ok(true),
            Ok(_) => Ok(false),
            // geth's estimator raises the limit on these, it does not bail out.
            Err(EvmError::IntrinsicGasTooLow { .. } | EvmError::FloorDataGasTooLow { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `eth_call` for a full transaction object (#509): every field the request
    /// names is applied, as [`Self::estimate_tx`] applies it — authorization
    /// list, access list, gas, fees, nonce, type — or the request is refused
    /// ([`EvmError::InvalidRequest`]); `overrides` are layered over verified
    /// state for this call only. Semantics are geth's `eth_call`:
    ///
    /// - `gas` is the call's gas limit, capped at [`VIEW_CALL_GAS`] as geth caps
    ///   it at its RPC gas cap; absent, the call gets the whole budget. A limit
    ///   below the intrinsic cost or the EIP-7623 floor is geth's
    ///   `intrinsic gas too low` / `insufficient gas for floor data gas cost`,
    ///   and running out of a limit the caller set is its `out of gas`.
    /// - A non-zero fee (a legacy `gasPrice`, or `maxFeePerGas`) must reach the
    ///   block's base fee, and the run sees the sender debited `gas × effective
    ///   price` and GASPRICE reading that price.
    /// - Fee or not, the sender must hold `gas × fee cap + value` (geth's
    ///   `buyGas`): a call moving more than the sender holds is refused as the
    ///   chain would refuse it, never run against a balance it does not have.
    ///
    /// Those answers are [`EvmError::is_infeasible`]: geth's message, never
    /// return data — a check failed before the run wrapped as geth's `eth_call`
    /// wraps it ([`EvmError::CallFailed`]).
    pub fn call_tx(
        &self,
        tx: &TxRequest,
        ctx: &BlockContext,
        overrides: StateOverrides,
    ) -> Result<Vec<u8>, EvmError> {
        self.call_tx_capped(tx, ctx, overrides, PREFETCH_ITERATION_CAP)
    }

    /// Run `tx` once at `gas_limit` as a block would include it and return
    /// revm's whole result, logs included. Test tooling for recorded-world
    /// replays (the `fixture` feature): it skips the call path's checks, and
    /// nothing a wallet sees answers from it.
    #[cfg(any(test, feature = "fixture"))]
    pub fn run_tx(
        &self,
        tx: &TxRequest,
        gas_limit: u64,
        ctx: &BlockContext,
        overrides: StateOverrides,
    ) -> Result<ExecutionResult, EvmError> {
        let spec = spec_for_context(ctx)?;
        let db = self.database_for_with(ctx, with_sender_nonce(overrides, tx)?);
        self.execute_with_db(&db, spec, tx, gas_limit, ctx)
    }

    fn call_tx_capped(
        &self,
        tx: &TxRequest,
        ctx: &BlockContext,
        overrides: StateOverrides,
        cap: usize,
    ) -> Result<Vec<u8>, EvmError> {
        self.oracle.check_request()?;
        let spec = spec_for_context(ctx)?;
        check_tx(tx, ctx, spec)?;
        // Refusals of the request itself first — a nonce contradicting the
        // override included — exactly as for an estimate.
        let db = self.database_for_with(ctx, with_sender_nonce(overrides, tx)?);
        let gas_limit = tx.gas.map_or(VIEW_CALL_GAS, |gas| gas.min(VIEW_CALL_GAS));
        // Then geth's checks before the run, in its order, each reported with
        // the limit it was made against — geth's `err: … (supplied gas N)`.
        let supplied = |error: EvmError| EvmError::CallFailed { supplied_gas: gas_limit, error: Box::new(error) };
        check_fee_cap(tx, ctx).map_err(supplied)?;
        // geth's buyGas, fee or no fee. Checked here, not by revm: its own
        // balance check would read a prefetch placeholder on a discovery pass,
        // and here the read also primes the sender before the first pass.
        if let Some(short) = buy_gas_shortfall(&db, tx, gas_limit)? {
            return Err(supplied(short));
        }
        let fee_cap = tx.fees.fee_cap();
        // revm prices the run as `gas × price` in u128 and `expect`s it not to
        // overflow — with its own balance check off nothing else stops it, and
        // a panic aborts the host. Only a balance overridden past 2^128 wei
        // gets here with such a price: nothing on chain can pay it.
        if u128::from(gas_limit).checked_mul(fee_cap).is_none() {
            return Err(EvmError::InvalidRequest {
                detail: format!("gas × fee cap ({gas_limit} × {fee_cap}) exceeds the 2^128 wei this engine can price"),
            });
        }
        match self.run_converged(&db, spec, tx, gas_limit, ctx, cap) {
            // Running dry is the caller's answer under a limit the caller set. A
            // larger one was capped to the budget, so running dry there is
            // refused rather than answered for a smaller limit. Without one it
            // stays the ordinary out-of-gas at this executor's own budget.
            Err(EvmError::OutOfGas) => Err(match tx.gas {
                Some(gas) if gas <= VIEW_CALL_GAS => EvmError::CallOutOfGas,
                Some(gas) => EvmError::CallBudgetExceeded { budget: VIEW_CALL_GAS, requested: gas },
                None => EvmError::OutOfGas,
            }),
            // The intrinsic cost or the floor above the limit: checks before the
            // run too, which revm makes.
            Err(error @ (EvmError::IntrinsicGasTooLow { .. } | EvmError::FloorDataGasTooLow { .. })) => {
                Err(supplied(error))
            }
            other => other,
        }
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

    /// One `transact` of `tx` at `gas_limit` against a caller-owned database —
    /// the shared setup of the call and estimate paths. Only DB / tx-envelope
    /// failures become `Err` here; execution outcomes (success/revert/halt) are
    /// returned for the caller to interpret. (The convergence loop shares ONE
    /// database — and thus one per-call view cache — across all of its
    /// iterations, so fetched state carries forward.)
    fn execute_with_db(
        &self,
        db: &OracleDatabase,
        spec: SpecId,
        tx: &TxRequest,
        gas_limit: u64,
        ctx: &BlockContext,
    ) -> Result<ExecutionResult, EvmError> {
        self.oracle.check_request()?;
        let cfg = view_cfg(spec, ctx.chain_id);
        let tx = tx_env(tx, gas_limit, ctx.chain_id)?;

        let mut evm = Context::mainnet()
            .with_ref_db(db)
            .with_block(ctx.block_env())
            .with_cfg(cfg)
            .build_mainnet_with_inspector(RequestInspector(self.oracle.as_ref()));

        let result = evm.inspect_tx(tx);
        // Cancellation takes precedence over an interpreter stop (including a
        // cancelled nested call) or a just-finished indivisible precompile.
        self.oracle.check_request()?;
        Ok(result.map_err(map_evm_error)?.result)
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
        self.oracle.check_request()?;
        let spec = spec_for_context(ctx)?;
        let db = self.database_for_with(ctx, overrides);
        // `None` ⇒ CONTRACT CREATION: `eth_call` with no `to`, where the
        // "constructor" runs and its RETURN DATA is the answer. Wallets use this
        // to run a helper contract they never deploy (Ambire's deployless Deploy
        // mode), which is the same job as a state override by another route.
        let tx = TxRequest::call(caller.into_array(), target, Bytes::copy_from_slice(calldata), value);
        self.run_converged(&db, spec, &tx, VIEW_CALL_GAS, ctx, cap).map_err(|e| match e {
            // Calldata that alone costs more than the budget: geth's answer for
            // a call at its gas cap, worded as its eth_call words it.
            error @ (EvmError::IntrinsicGasTooLow { .. } | EvmError::FloorDataGasTooLow { .. }) => {
                EvmError::CallFailed { supplied_gas: VIEW_CALL_GAS, error: Box::new(error) }
            }
            other => other,
        })
    }

    /// Run `tx` at `gas_limit` to convergence and return its output bytes
    /// (revert/halt → `Err`): the loop behind every call entry point, over a
    /// caller-built database (overrides and the sender's nonce already
    /// layered in).
    fn run_converged(
        &self,
        db: &OracleDatabase,
        spec: SpecId,
        tx: &TxRequest,
        gas_limit: u64,
        ctx: &BlockContext,
        cap: usize,
    ) -> Result<Vec<u8>, EvmError> {
        // Prime the target's account + code synchronously (sentinel OFF, not
        // access-tracked — Java parity) so iteration 0 executes real top-level
        // code instead of a sentinel empty account.
        // A create has no target account to prime; its code is the calldata.
        if let Some(to) = tx.to {
            if let Some(acc) = db.basic_ref(Address::from(to))? {
                db.code_by_hash_ref(acc.code_hash)?;
            }
        }
        let _ = db.take_access_set(); // the prime is not part of any snapshot

        let mut seen = AccessSet::default();
        let mut discovering = true;
        for iter in 0..cap {
            self.oracle.check_request()?;
            // Sentinel while still discovering, but the LAST TWO iterations are
            // always real (one final wave + one warm real run).
            let sentinel = discovering && iter + 2 < cap;
            db.set_sentinel(sentinel);
            let misses_before = db.sentinel_misses();
            let outcome = self.execute_with_db(db, spec, tx, gas_limit, ctx);
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
}

/// The spec `ctx` executes under ([`spec_for`]), refusing a context that
/// cannot serve it: an AMSTERDAM block whose header carried no EIP-7843 slot
/// number would run SLOTNUM against a made-up 0 — a well-formed wrong answer —
/// so it fails with the permanent [`EvmError::MissingSlotNumber`] before any
/// state is fetched. Before Amsterdam the slot is not needed (SLOTNUM is an
/// invalid opcode there) — and a header that carries one anyway is an
/// Amsterdam block this build's fork table does not know about, refused the
/// same way ([`EvmError::UnexpectedSlotNumber`]) rather than run under the
/// older fork's rules.
fn spec_for_context(ctx: &BlockContext) -> Result<SpecId, EvmError> {
    let spec = spec_for(ctx.chain_id, ctx.block_number, ctx.timestamp)?;
    let amsterdam = spec.is_enabled_in(SpecId::AMSTERDAM);
    if amsterdam && ctx.slot_number.is_none() {
        return Err(EvmError::MissingSlotNumber {
            block_number: ctx.block_number,
        });
    }
    if !amsterdam && ctx.slot_number.is_some() {
        return Err(EvmError::UnexpectedSlotNumber {
            block_number: ctx.block_number,
        });
    }
    Ok(spec)
}

/// The [`CfgEnv`] a view call runs under at `spec`: revm's per-spec defaults
/// with the transaction-level checks relaxed (see the module docs).
///
/// Amsterdam's gas model — EIP-8037 state gas and EIP-2780 decomposed intrinsic
/// gas — is on for AMSTERDAM specs and off for every earlier one. That is exactly
/// what reth runs Amsterdam blocks with: it builds its env with this same
/// `CfgEnv::new_with_spec` (alloy-evm `EvmEnv::for_eth`), which derives both
/// flags from the spec, and sets no Amsterdam flag of its own — revm's EIP-7708 /
/// EIP-8246 opt-outs stay at their defaults (active from AMSTERDAM, gated inside
/// revm). The explicit assignment restates that derivation so a revm bump that
/// stopped making it can't silently price Amsterdam with Osaka's gas model;
/// `amsterdam_gas_model_is_enabled_only_for_amsterdam` pins the result.
fn view_cfg(spec: SpecId, chain_id: u64) -> CfgEnv {
    let mut cfg = CfgEnv::new_with_spec(spec);
    cfg.chain_id = chain_id;
    let amsterdam = spec.is_enabled_in(SpecId::AMSTERDAM);
    cfg.enable_amsterdam_eip8037 = amsterdam;
    cfg.enable_amsterdam_eip2780 = amsterdam;
    // Not a real tx: relax the transaction-level checks (see the module docs).
    // `tx_gas_limit_cap` is raised to VIEW_CALL_GAS so the spec's own per-tx cap
    // doesn't clip the full-block gas budget (also the estimate ceiling). Under
    // EIP-8037 the cap also splits regular gas from the state-gas reservoir; at
    // cap == gas limit the reservoir is empty and state gas draws on the same
    // 30 M, so the budget means the same thing on every fork.
    cfg.disable_nonce_check = true;
    cfg.disable_balance_check = true;
    cfg.disable_base_fee = true;
    cfg.disable_eip3607 = true;
    cfg.disable_block_gas_limit = true;
    cfg.tx_gas_limit_cap = Some(VIEW_CALL_GAS);
    cfg
}

/// The revm [`TxEnv`] for `tx` at `gas_limit`, built with the STRICT
/// `TxEnvBuilder::build`: `build_fill` would quietly repair a request into a
/// different transaction (a dummy authorization for an empty type-4 list, a call
/// to the zero address for a type-4 creation) — the silently-wrong answer
/// [`TxRequest::validate`] refuses before we get here.
fn tx_env(tx: &TxRequest, gas_limit: u64, chain_id: u64) -> Result<TxEnv, EvmError> {
    let ty = tx.tx_type();
    // geth's pricing: a legacy `gasPrice` is both the fee cap and the tip, and a
    // missing dynamic-fee field is zero. revm reads `gas_price` as THE price below
    // type 2 and as the fee cap from type 2 on, where the effective price (what
    // GASPRICE reads) is min(cap, basefee + tip).
    let (gas_price, tip) = match tx.fees {
        Fees::None => (0, 0),
        Fees::Legacy { gas_price } => (gas_price, gas_price),
        Fees::DynamicFee { max_fee_per_gas, max_priority_fee_per_gas } => {
            (max_fee_per_gas, max_priority_fee_per_gas)
        }
    };
    let access_list = AccessList(
        tx.access_list
            .iter()
            .flatten()
            .map(|item| RevmAccessListItem {
                address: Address::from(item.address),
                storage_keys: item.storage_keys.iter().map(|k| B256::from(*k)).collect(),
            })
            .collect(),
    );
    // Signed, not pre-recovered: revm recovers each authority itself and treats
    // an unrecoverable tuple as invalid-and-skipped, exactly as on chain.
    let authorizations = tx
        .authorization_list
        .iter()
        .flatten()
        .map(|a| {
            SignedAuthorization::new_unchecked(
                RevmAuthorization { chain_id: a.chain_id, address: Address::from(a.address), nonce: a.nonce },
                a.y_parity,
                a.r,
                a.s,
            )
        })
        .collect();
    TxEnv::builder()
        .tx_type(Some(ty))
        .caller(Address::from(tx.from))
        .kind(match tx.to {
            Some(to) => TxKind::Call(Address::from(to)),
            None => TxKind::Create,
        })
        .value(tx.value)
        .data(tx.data.clone())
        .gas_limit(gas_limit)
        .gas_price(gas_price)
        .gas_priority_fee((ty >= TYPE_DYNAMIC_FEE).then_some(tip))
        // Validation is off (`disable_nonce_check`): the sender's nonce as the run
        // sees it comes from `with_sender_nonce`, this only has to be in range.
        .nonce(tx.nonce.unwrap_or(0))
        // Always the node's chain: build() defaults the tx chain id to MAINNET
        // (Some(1)), which revm validates against cfg.chain_id — on any other
        // chain the call would die with "invalid chain ID" (found live on
        // sepolia). A request naming another chain was refused before this.
        .chain_id(Some(chain_id))
        .access_list(access_list)
        .authorization_list_signed(authorizations)
        .build()
        .map_err(|e| EvmError::InvalidRequest { detail: e.to_string() })
}

/// The request-level checks every transaction-object entry point shares, run
/// before any state is read: the object must describe a transaction that could
/// exist ([`TxRequest::validate`]), for this node's chain, of a type the
/// block's fork knows.
fn check_tx(tx: &TxRequest, ctx: &BlockContext, spec: SpecId) -> Result<(), EvmError> {
    tx.validate().map_err(|detail| EvmError::InvalidRequest { detail })?;
    if let Some(chain_id) = tx.chain_id {
        if chain_id != U256::from(ctx.chain_id) {
            return Err(EvmError::InvalidRequest {
                detail: format!("chainId {chain_id} does not match this node's chain ({})", ctx.chain_id),
            });
        }
    }
    if tx.tx_type() == TYPE_SET_CODE && !spec.is_enabled_in(SpecId::PRAGUE) {
        return Err(EvmError::InvalidRequest {
            detail: "EIP-7702 transactions are not valid before Prague".into(),
        });
    }
    Ok(())
}

/// A non-zero fee cap (a legacy gas price is its own cap) below the block's
/// base fee names a transaction no block at that base fee includes: geth
/// answers `max fee per gas less than block base fee` for a call and an
/// estimate alike. No fee at all is the fee-less simulation geth exempts, and
/// so do we (revm's own base-fee check stays off for it: `view_cfg`).
fn check_fee_cap(tx: &TxRequest, ctx: &BlockContext) -> Result<(), EvmError> {
    let fee_cap = tx.fees.fee_cap();
    if fee_cap > 0 && fee_cap < u128::from(ctx.base_fee_per_gas) {
        return Err(EvmError::FeeCapTooLow {
            address: tx.from,
            fee_cap,
            base_fee: ctx.base_fee_per_gas,
        });
    }
    Ok(())
}

/// geth's buyGas: the sender must hold `gas_limit × fee cap + value`, a sum
/// that must fit 256 bits — the shortfall as geth's error, or `None`. The
/// balance is the one the run will see (overrides included), and is not read
/// when nothing is owed. ONE copy for a call and an estimate.
fn buy_gas_shortfall(db: &OracleDatabase, tx: &TxRequest, gas_limit: u64) -> Result<Option<EvmError>, EvmError> {
    let Some(want) = U256::from(gas_limit)
        .checked_mul(U256::from(tx.fees.fee_cap()))
        .and_then(|cost| cost.checked_add(tx.value))
    else {
        return Ok(Some(EvmError::RequiredBalanceOverflow { address: tx.from }));
    };
    if want.is_zero() {
        return Ok(None);
    }
    let have = db.basic_ref(Address::from(tx.from))?.map_or(U256::ZERO, |a| a.balance);
    Ok((have < want).then_some(EvmError::InsufficientFunds { address: tx.from, have, want }))
}

/// Layer the request's `nonce` over the sender's account, so the run sees the
/// nonce the transaction will execute at: a self-sponsored EIP-7702
/// authorization is checked against it + 1 (the sender's nonce is bumped
/// first), and a creation derives its address from it. revm's own
/// nonce check stays off — this is the one place the value enters the run. A
/// state override naming a DIFFERENT nonce for the sender asks a contradictory
/// question and is refused.
fn with_sender_nonce(mut overrides: StateOverrides, tx: &TxRequest) -> Result<StateOverrides, EvmError> {
    let Some(nonce) = tx.nonce else {
        return Ok(overrides);
    };
    let mut entry = overrides.get(&tx.from).cloned().unwrap_or_default();
    if let Some(overridden) = entry.nonce.filter(|n| *n != nonce) {
        return Err(EvmError::InvalidRequest {
            detail: format!(
                "nonce {nonce} contradicts the state override's nonce {overridden} for the sender"
            ),
        });
    }
    entry.nonce = Some(nonce);
    overrides.insert(tx.from, entry);
    Ok(overrides)
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
        // The gas limit does not even cover the intrinsic cost (or the EIP-7623
        // floor): geth's call-side answers. An estimate reads both as its
        // caller's allowance instead (`estimate_tx`), as geth does.
        EVMError::Transaction(InvalidTransaction::CallGasCostMoreThanGasLimit { initial_gas, gas_limit }) => {
            EvmError::IntrinsicGasTooLow { have: gas_limit, want: initial_gas }
        }
        EVMError::Transaction(InvalidTransaction::GasFloorMoreThanGasLimit { gas_floor, gas_limit }) => {
            EvmError::FloorDataGasTooLow { have: gas_limit, want: gas_floor }
        }
        // A creation whose init code exceeds EIP-3860's limit can never run:
        // the request's own fault, so a permanent refusal (geth: "max initcode
        // size exceeded"), never the retryable "unavailable".
        EVMError::Transaction(InvalidTransaction::CreateInitCodeSizeLimit) => EvmError::InvalidRequest {
            detail: "max initcode size exceeded (EIP-3860)".into(),
        },
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

    /// The mainnet RelayAdapt7702 shield, replayed from its recorded world (#509).
    mod relay_adapt_7702_shield;

    struct CancelledOracle;
    impl SnapStateOracle for CancelledOracle {
        fn check_request(&self) -> Result<(), OracleError> {
            Err(OracleError::Cancelled { reason: "test cancellation".into() })
        }
        fn fetch_account(&self, _: &[u8; 32], _: [u8; 20]) -> Result<Option<OracleAccount>, OracleError> {
            panic!("cancelled executor must not fetch")
        }
        fn fetch_storage(&self, _: &[u8; 32], _: [u8; 20], _: U256) -> Result<U256, OracleError> {
            panic!("cancelled executor must not fetch")
        }
        fn fetch_bytecode(&self, _: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
            panic!("cancelled executor must not fetch")
        }
    }

    #[test]
    fn cancelled_call_and_estimate_refuse_before_fetch() {
        let executor = EvmExecutor::new(Arc::new(CancelledOracle), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache));
        let context = ctx(LONDON_BLOCK, CANCUN_TIME);
        assert!(matches!(executor.call_view(TARGET, &[], &context), Err(EvmError::Oracle(OracleError::Cancelled { .. }))));
        assert!(matches!(executor.estimate_gas([0; 20], TARGET, &[], U256::ZERO, &context), Err(EvmError::Oracle(OracleError::Cancelled { .. }))));
    }

    #[test]
    fn cancelled_instruction_sets_stop_without_running_bytecode() {
        let mut interpreter = Interpreter::default_ext();
        RequestInspector(&CancelledOracle).step(&mut interpreter, &mut ());
        assert!(interpreter.bytecode.action().is_some());
    }

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
            slot_number: None, // mainnet has no Amsterdam date: no slot in the header
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
        let eoa = |balance: u64| OracleAccount {
            nonce: 1,
            balance: U256::from(balance),
            code_hash: myotis_core::trie::EMPTY_CODE_HASH,
            storage_root: [0x9; 32],
        };
        // The sender can cover the value it moves (geth's buyGas holds at fee 0).
        let fx = FixtureSnapStateOracle::new()
            .with_account(ROOT, TARGET, eoa(1_000_000))
            .with_account(ROOT, [0x42; 20], eoa(1));
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
            let db = exec.database_for_with(&c, StateOverrides::new());
            let tx = TxRequest::call([0u8; 20], Some(TARGET), Bytes::new(), U256::ZERO);
            match exec.execute_with_db(&db, spec, &tx, VIEW_CALL_GAS, &c).unwrap()
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

    // ---- eth_estimateGas over the full transaction object (#509) ----------

    use crate::tx::{AccessListItem, Authorization, Fees};
    use myotis_core::nodekey::NodeKey;
    use myotis_core::trie::EMPTY_CODE_HASH;
    use revm::context_interface::Transaction;

    const SENDER: [u8; 20] = [0x42; 20];
    const DELEGATE: [u8; 20] = [0xDE; 20];

    /// A fixture world of `(address, code, balance, nonce)` accounts — codeless
    /// entries are plain EOAs; every other address is absent (a fresh account).
    fn executor_with_accounts(accounts: &[([u8; 20], Vec<u8>, U256, u64)]) -> EvmExecutor {
        let mut fx = FixtureSnapStateOracle::new();
        for (address, code, balance, nonce) in accounts {
            let code_hash = if code.is_empty() { EMPTY_CODE_HASH } else { fx.with_bytecode(code.clone()) };
            fx = fx.with_account(
                ROOT,
                *address,
                OracleAccount { nonce: *nonce, balance: *balance, code_hash, storage_root: [0x9; 32] },
            );
        }
        EvmExecutor::new(Arc::new(fx), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache))
    }

    /// `n` fresh-slot SSTOREs (slot i := 1), then STOP — 22100 gas each, the
    /// kind of work a delegated shield does.
    fn sstores(n: u8) -> Vec<u8> {
        let mut code = Vec::new();
        for slot in 0..n {
            code.extend_from_slice(&[0x60, 0x01, 0x60, slot, 0x55]);
        }
        code.push(0x00);
        code
    }

    fn key(byte: u8) -> NodeKey {
        NodeKey::from_secret_bytes(&[byte; 32]).unwrap()
    }

    fn address_of(key: &NodeKey) -> [u8; 20] {
        keccak256(&key.public_key_bytes())[12..].try_into().unwrap()
    }

    /// An EIP-7702 authorization signed by `key`: keccak(0x05 ‖ rlp([chain_id,
    /// address, nonce])), low-s.
    fn sign_authorization(key: &NodeKey, chain_id: u64, delegate: [u8; 20], nonce: u64) -> Authorization {
        let hash = RevmAuthorization { chain_id: U256::from(chain_id), address: Address::from(delegate), nonce }
            .signature_hash();
        let sig = key.sign_hash(&hash.0).unwrap();
        Authorization {
            chain_id: U256::from(chain_id),
            address: delegate,
            nonce,
            y_parity: sig[64],
            r: U256::from_be_slice(&sig[..32]),
            s: U256::from_be_slice(&sig[32..64]),
        }
    }

    fn prague() -> BlockContext {
        use crate::fork::PRAGUE_TIME;
        ctx(22_500_000, PRAGUE_TIME + 1)
    }

    /// A type-4 request: `from` calls `to` with a selector-sized payload.
    fn set_code_call(from: [u8; 20], to: [u8; 20], auths: Vec<Authorization>) -> TxRequest {
        let mut tx = TxRequest::call(from, Some(to), Bytes::from(vec![0x3e, 0x12, 0xcc, 0x2e]), U256::ZERO);
        tx.tx_type = Some(TYPE_SET_CODE);
        tx.authorization_list = Some(auths);
        tx
    }

    /// The lowest gas limit at which `tx` runs, found exactly by bisecting
    /// over call outcomes (the transactions in these tests are monotone in it).
    /// Only an ANSWER counts as "does not run" — anything else fails the test.
    fn lowest_limit_that_runs(exec: &EvmExecutor, tx: &TxRequest, c: &BlockContext) -> u64 {
        crate::fixture::lowest_limit_that_runs(exec, tx, c, &StateOverrides::new()).unwrap()
    }

    /// `estimate` is the search's answer for `tx`: the lowest limit that runs,
    /// within geth's 1.5%, plus the 1.15 buffer — and itself a limit that runs.
    fn assert_is_the_searched_estimate(exec: &EvmExecutor, tx: &TxRequest, c: &BlockContext, estimate: u64) {
        let lowest = lowest_limit_that_runs(exec, tx, c);
        let (lower, upper) = (with_estimate_buffer(lowest), with_estimate_buffer(lowest * 10_153 / 10_000 + 1));
        assert!(
            (lower..=upper).contains(&estimate),
            "estimate {estimate} is not the searched answer over the lowest limit {lowest} ({lower}..={upper})"
        );
        let mut at_estimate = tx.clone();
        at_estimate.gas = Some(estimate);
        exec.call_tx(&at_estimate, c, StateOverrides::new()).expect("the estimate must be a limit that runs");
    }

    /// What one run at the budget drew, gross — the old one-run estimate's base.
    fn drawn_at_the_budget(exec: &EvmExecutor, tx: &TxRequest, c: &BlockContext) -> u64 {
        let spec = spec_for_context(c).unwrap();
        let db = exec.database_for_with(c, StateOverrides::new());
        match exec.execute_with_db(&db, spec, tx, VIEW_CALL_GAS, c).unwrap() {
            ExecutionResult::Success { gas, .. } => gas.total_gas_spent().max(gas.tx_gas_used()),
            other => panic!("the transaction must run at the budget, got {other:?}"),
        }
    }

    /// CALL `next` with all remaining gas, and revert if it failed.
    fn forwarder(next: [u8; 20]) -> Vec<u8> {
        let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        code.extend_from_slice(&next);
        // GAS CALL ISZERO PUSH1 38 JUMPI STOP JUMPDEST PUSH1 0 DUP1 REVERT
        code.extend_from_slice(&[0x5a, 0xf1, 0x15, 0x60, 0x26, 0x57, 0x00, 0x5b, 0x60, 0x00, 0x80, 0xfd]);
        code
    }

    /// #509 stage 2: a call chain withholds 1/64 of the gas at every level
    /// (EIP-150), so the limit that works grows as (64/63)^depth over the
    /// innermost work — past the 1.15 a single run's draw was buffered with.
    /// The search finds the limit that works.
    #[test]
    fn estimate_covers_the_gas_nested_calls_withhold() {
        const DEPTH: u8 = 20;
        let level = |i: u8| {
            let mut address = [0x60; 20];
            address[19] = i;
            address
        };
        let mut accounts: Vec<([u8; 20], Vec<u8>, U256, u64)> =
            (0..DEPTH).map(|i| (level(i), forwarder(level(i + 1)), U256::ZERO, 1)).collect();
        accounts.push((level(DEPTH), sstores(14), U256::ZERO, 1));
        let exec = executor_with_accounts(&accounts);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let tx = TxRequest::call(SENDER, Some(level(0)), Bytes::new(), U256::ZERO);

        let estimate = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        assert_is_the_searched_estimate(&exec, &tx, &c, estimate);
        // The one-run answer is a limit the transaction fails at.
        let mut one_run = tx.clone();
        one_run.gas = Some(with_estimate_buffer(drawn_at_the_budget(&exec, &tx, &c)));
        assert!(exec.call_tx(&one_run, &c, StateOverrides::new()).is_err(), "the one-run estimate should fail here");
    }

    /// A refund-heavy transaction is charged far less than it needs to run:
    /// clearing slots refunds up to a fifth of the gas, at the end. The
    /// search starts from the charge but answers what the run needs.
    #[test]
    fn estimate_covers_a_refund_heavy_transaction() {
        // Ten `SSTORE(slot i, 0)` over slots holding 1, then STOP.
        let mut code = Vec::new();
        for slot in 0..10u8 {
            code.extend_from_slice(&[0x60, 0x00, 0x60, slot, 0x55]);
        }
        code.push(0x00);
        let mut fx = FixtureSnapStateOracle::new();
        let code_hash = fx.with_bytecode(code);
        fx = fx.with_account(ROOT, TARGET, OracleAccount { nonce: 1, balance: U256::ZERO, code_hash, storage_root: [0x9; 32] });
        for slot in 0..10u8 {
            let mut key = [0u8; 32];
            key[31] = slot;
            fx = fx.with_storage(ROOT, TARGET, key, U256::from(1u64));
        }
        let exec = EvmExecutor::new(Arc::new(fx), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache));
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);

        let charged = mined_gas_used(&exec, &tx, VIEW_CALL_GAS, &c);
        let lowest = lowest_limit_that_runs(&exec, &tx, &c);
        assert!(charged + 10_000 < lowest, "refunds should put the charge ({charged}) well below the need ({lowest})");
        assert_is_the_searched_estimate(&exec, &tx, &c, exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap());
    }

    /// A contract that checks `gasleft()` draws little at the budget yet
    /// reverts at any limit that leaves it short: only a search sees that.
    #[test]
    fn estimate_covers_a_gasleft_check() {
        // GAS PUSH3 100000 LT ISZERO PUSH1 11 JUMPI STOP JUMPDEST PUSH1 0 DUP1 REVERT
        // — revert unless gasleft() > 100000.
        let code = vec![0x5a, 0x62, 0x01, 0x86, 0xa0, 0x10, 0x15, 0x60, 0x0b, 0x57, 0x00, 0x5b, 0x60, 0x00, 0x80, 0xfd];
        let exec = executor_with_accounts(&[(TARGET, code, U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);

        let estimate = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        assert!(estimate > 100_000, "the estimate must leave the contract its 100000: {estimate}");
        assert_is_the_searched_estimate(&exec, &tx, &c, estimate);
        let mut one_run = tx.clone();
        one_run.gas = Some(with_estimate_buffer(drawn_at_the_budget(&exec, &tx, &c)));
        assert!(exec.call_tx(&one_run, &c, StateOverrides::new()).is_err(), "the one-run estimate should revert here");
    }

    /// Without a fee geth still holds the sender to the value it moves.
    #[test]
    fn a_fee_less_estimate_moving_more_than_the_sender_holds_is_geths_answer() {
        let exec = executor_with_accounts(&[(SENDER, vec![], U256::from(5u64), 0), (TARGET, vec![0x00], U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        for to in [TARGET, DELEGATE] {
            // A contract, and a codeless account (the 21000 short-circuit).
            let tx = TxRequest::call(SENDER, Some(to), Bytes::new(), U256::from(6u64));
            let err = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap_err();
            let short = EvmError::InsufficientFunds { address: SENDER, have: U256::from(5u64), want: U256::from(6u64) };
            assert_eq!(err, EvmError::FailedWithGas { gas: VIEW_CALL_GAS, error: Box::new(short) });
            assert!(err.is_infeasible());
            assert_eq!(
                err.to_string(),
                "failed with 30000000 gas: insufficient funds for gas * price + value: address \
                 0x4242424242424242424242424242424242424242 have 5 want 6"
            );
        }
        // All of it is fine.
        let tx = TxRequest::call(SENDER, Some(DELEGATE), Bytes::new(), U256::from(5u64));
        assert_eq!(exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap(), PLAIN_TRANSFER_GAS);
    }

    /// No block holds a transaction above its gas limit: geth's search starts
    /// there, and so does the ceiling.
    #[test]
    fn the_block_gas_limit_bounds_the_estimate() {
        let exec = executor_with_accounts(&[(TARGET, sstores(10), U256::ZERO, 1)]);
        let mut c = ctx(19_500_000, CANCUN_TIME + 1);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        assert!(exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap() > 200_000);
        c.gas_limit = 200_000;
        assert_eq!(
            exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap_err(),
            EvmError::GasAllowanceExceeded { allowance: 200_000 }
        );
        // Only a default, as in geth: the caller's own `gas` replaces it.
        let mut limited = tx.clone();
        limited.gas = Some(250_000);
        assert_eq!(exec.estimate_tx(&limited, &c, StateOverrides::new()).unwrap(), 250_000);
    }

    /// Below what the run at the ceiling drew, a limit can only "work" by
    /// running a different transaction: here one whose inner call fails and
    /// the outer contract swallows it. Clearing storage first refunds a fifth
    /// of the draw, so what the run is CHARGED — where geth's search starts —
    /// is such a limit; this search never goes below the draw, so the call the
    /// caller simulated happens at the estimate. One level deep, as
    /// `lowest_working_limit` bounds it: the buffer covers a caught failure
    /// through 8 levels.
    #[test]
    fn estimate_covers_a_swallowed_call_one_level_deep() {
        let inner = [0x77; 20];
        // SSTORE(slot i, 0) over ten slots holding 1 (refunds), then CALL inner
        // with all gas and return the success flag, whatever it is.
        let mut outer = Vec::new();
        for slot in 0..10u8 {
            outer.extend_from_slice(&[0x60, 0x00, 0x60, slot, 0x55]);
        }
        outer.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73]);
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&[0x5a, 0xf1, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
        let mut fx = FixtureSnapStateOracle::new();
        let outer_hash = fx.with_bytecode(outer);
        let inner_hash = fx.with_bytecode(sstores(5));
        let account = |code_hash| OracleAccount { nonce: 1, balance: U256::ZERO, code_hash, storage_root: [0x9; 32] };
        fx = fx.with_account(ROOT, TARGET, account(outer_hash)).with_account(ROOT, inner, account(inner_hash));
        for slot in 0..10u8 {
            let mut key = [0u8; 32];
            key[31] = slot;
            fx = fx.with_storage(ROOT, TARGET, key, U256::from(1u64));
        }
        let exec = EvmExecutor::new(Arc::new(fx), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache));
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        let flag = |gas: u64| {
            let mut limited = tx.clone();
            limited.gas = Some(gas);
            word(&exec.call_tx(&limited, &c, StateOverrides::new()).unwrap())
        };
        // At what the run is charged, the transaction still "runs" — without
        // its inner call.
        let charged = mined_gas_used(&exec, &tx, VIEW_CALL_GAS, &c);
        assert!(charged < drawn_at_the_budget(&exec, &tx, &c));
        assert_eq!(flag(charged), U256::ZERO);

        let estimate = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        assert!(estimate >= with_estimate_buffer(drawn_at_the_budget(&exec, &tx, &c)));
        assert_eq!(flag(estimate), U256::from(1u64), "at the estimate the inner call must succeed");
    }

    /// Run `tx` at `gas_limit` as a mined transaction would, returning the gas it
    /// uses — or panic if it does not succeed.
    fn mined_gas_used(exec: &EvmExecutor, tx: &TxRequest, gas_limit: u64, c: &BlockContext) -> u64 {
        let spec = spec_for_context(c).unwrap();
        let db = exec.database_for_with(c, with_sender_nonce(StateOverrides::new(), tx).unwrap());
        match exec.execute_with_db(&db, spec, tx, gas_limit, c).unwrap() {
            ExecutionResult::Success { gas, .. } => gas.tx_gas_used(),
            other => panic!("the transaction must succeed at the estimate, got {other:?}"),
        }
    }

    /// THE #509 regression: a type-4 transaction whose authorization delegates a
    /// FRESH EOA and then calls it. Dropping the authorization list ran the
    /// call against an empty account and answered ~24k; the wallet's
    /// transaction then ran out of gas on chain.
    #[test]
    fn estimate_tx_applies_an_authorization_that_delegates_a_fresh_eoa() {
        let ephemeral = key(0x07);
        let authority = address_of(&ephemeral);
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10u64).pow(U256::from(18)), 3),
            (DELEGATE, sstores(10), U256::ZERO, 1),
        ]);
        let c = prague();
        let tx = set_code_call(SENDER, authority, vec![sign_authorization(&ephemeral, 1, DELEGATE, 0)]);

        let est = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        // Intrinsic 21000 + 25000 for the (new-account) authorization, plus ten
        // fresh SSTOREs the delegated code runs in the EOA's own storage.
        assert!(est >= 21_000 + 25_000 + 10 * 22_100, "estimate {est} must cover the delegated work");
        // And the mined transaction fits under it.
        let used = mined_gas_used(&exec, &tx, est, &c);
        assert!(used <= est, "mined gas {used} must not exceed the estimate {est}");

        // The pre-#509 answer for the same request: no authorization applied.
        let mut dropped = tx.clone();
        dropped.tx_type = None;
        dropped.authorization_list = None;
        let blind = exec.estimate_tx(&dropped, &c, StateOverrides::new()).unwrap();
        assert!(blind < 30_000, "without the list the call hits an empty account: {blind}");
    }

    /// A call into a delegated account starts with the delegate warm (the
    /// execution specs' `process_message_call`; geth's convenience warming).
    /// The Java `DelegatedTargetTest` pins the same number: its engine charged
    /// a cold access here, 2500 gas above this one on the RAILGUN shield.
    #[test]
    fn a_delegated_targets_delegate_starts_warm() {
        let (target, delegate, other) = ([0x22; 20], [0x33; 20], [0x44; 20]);
        // BALANCE of the delegate itself (warm: 100), then of an untouched
        // account (cold: 2600), then STOP.
        let mut code = vec![0x73];
        code.extend_from_slice(&delegate);
        code.extend_from_slice(&[0x31, 0x50, 0x73]);
        code.extend_from_slice(&other);
        code.extend_from_slice(&[0x31, 0x50, 0x00]);
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(&delegate);
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10u64).pow(U256::from(18)), 0),
            (target, designator, U256::ZERO, 1),
            (delegate, code, U256::ZERO, 1),
        ]);
        let tx = TxRequest::call(SENDER, Some(target), Bytes::new(), U256::ZERO);
        assert_eq!(drawn_at_the_budget(&exec, &tx, &prague()), 21_000 + 3 + 100 + 2 + 3 + 2_600 + 2);
    }

    /// A chain id of 0 authorizes on every chain (EIP-7702).
    #[test]
    fn estimate_tx_applies_a_chain_agnostic_authorization() {
        let ephemeral = key(0x08);
        let exec = executor_with_accounts(&[(DELEGATE, sstores(4), U256::ZERO, 1)]);
        let tx = set_code_call(SENDER, address_of(&ephemeral), vec![sign_authorization(&ephemeral, 0, DELEGATE, 0)]);
        let est = exec.estimate_tx(&tx, &prague(), StateOverrides::new()).unwrap();
        assert!(est >= 21_000 + 25_000 + 4 * 22_100, "got {est}");
    }

    /// An invalid tuple is SKIPPED, not fatal — the spec's rule, so the
    /// transaction still estimates (and still pays the tuple's intrinsic cost).
    #[test]
    fn estimate_tx_skips_an_invalid_authorization_like_the_chain_does() {
        let ephemeral = key(0x09);
        let exec = executor_with_accounts(&[(DELEGATE, sstores(10), U256::ZERO, 1)]);
        // Signed for chain 5 while the node is on chain 1.
        let tx = set_code_call(SENDER, address_of(&ephemeral), vec![sign_authorization(&ephemeral, 5, DELEGATE, 0)]);
        let est = exec.estimate_tx(&tx, &prague(), StateOverrides::new()).unwrap();
        assert!(est >= 21_000 + 25_000, "the tuple's intrinsic cost is still charged: {est}");
        assert!(est < 100_000, "a skipped tuple installs no delegation, so no SSTOREs run: {est}");
    }

    /// The request's nonce is the sender's nonce when the transaction runs: a
    /// self-sponsored authorization must carry it + 1 (the sender's nonce is
    /// bumped first). A queued transaction (nonce above the state nonce) only
    /// estimates right if that nonce is applied.
    #[test]
    fn estimate_tx_checks_a_self_sponsored_authorization_against_the_tx_nonce() {
        let wallet = key(0x0a);
        let me = address_of(&wallet);
        let exec = executor_with_accounts(&[
            (me, vec![], U256::from(10u64).pow(U256::from(18)), 5),
            (DELEGATE, sstores(10), U256::ZERO, 1),
        ]);
        let c = prague();
        // Queued behind one pending transaction: tx nonce 6 (state says 5), so
        // the authorization is signed for 7.
        let mut tx = set_code_call(me, me, vec![sign_authorization(&wallet, 1, DELEGATE, 7)]);
        tx.nonce = Some(6);
        let applied = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        assert!(applied >= 21_000 + 10 * 22_100, "nonce applied: the delegation runs: {applied}");

        // Without the nonce, the state nonce (5 → 6) rejects the tuple.
        tx.nonce = None;
        let unapplied = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        assert!(unapplied < 100_000, "state nonce: the tuple is skipped: {unapplied}");
    }

    #[test]
    fn estimate_tx_refuses_a_nonce_that_contradicts_a_sender_override() {
        use crate::overrides::AccountOverride;
        let exec = executor_with_accounts(&[(TARGET, vec![0x00], U256::ZERO, 1)]);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.nonce = Some(4);
        let mut ov = StateOverrides::new();
        ov.insert(SENDER, AccountOverride { nonce: Some(9), ..Default::default() });
        let err = exec.estimate_tx(&tx, &prague(), ov).unwrap_err();
        assert!(matches!(err, EvmError::InvalidRequest { .. }) && err.is_refusal(), "got {err:?}");
    }

    /// EIP-2930: each address costs 2400 and each key 1900 up front, and the
    /// listed slot is then warm (100) instead of cold (2100). Pinned exactly
    /// through the lowest limit that runs.
    #[test]
    fn estimate_tx_charges_and_prewarms_the_access_list() {
        // PUSH1 0; SLOAD; POP; STOP
        let exec = executor_with_accounts(&[(TARGET, vec![0x60, 0x00, 0x54, 0x50, 0x00], U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let bare = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        // 21000 + PUSH1 3 + cold SLOAD 2100 + POP 2
        assert_eq!(lowest_limit_that_runs(&exec, &bare, &c), 23_105);
        assert_is_the_searched_estimate(&exec, &bare, &c, exec.estimate_tx(&bare, &c, StateOverrides::new()).unwrap());
        let mut listed = bare.clone();
        listed.access_list = Some(vec![AccessListItem { address: TARGET, storage_keys: vec![[0u8; 32]] }]);
        // 21000 + 2400 + 1900 + 3 + warm SLOAD 100 + 2
        assert_eq!(lowest_limit_that_runs(&exec, &listed, &c), 25_405);
        assert_is_the_searched_estimate(&exec, &listed, &c, exec.estimate_tx(&listed, &c, StateOverrides::new()).unwrap());
    }

    /// A list changes a plain transfer's price, so the exact-21000 shortcut must
    /// not answer for it.
    #[test]
    fn estimate_tx_does_not_short_circuit_a_transfer_with_an_access_list() {
        let exec = executor_with_accounts(&[(SENDER, vec![], U256::from(1u64), 0)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::from(1u64));
        assert_eq!(exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap(), PLAIN_TRANSFER_GAS);
        tx.access_list = Some(vec![AccessListItem { address: DELEGATE, storage_keys: vec![] }]);
        // 21000 + 2400, searched and buffered like any metered estimate.
        assert_eq!(lowest_limit_that_runs(&exec, &tx, &c), 23_400);
        assert_is_the_searched_estimate(&exec, &tx, &c, exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap());
    }

    /// `gas` is the ceiling: the answer never exceeds it, a transaction that
    /// needs more is geth's "gas required exceeds allowance", and below 21000
    /// it is no limit at all (geth's reading).
    #[test]
    fn estimate_tx_never_answers_above_the_callers_gas() {
        let exec = executor_with_accounts(&[(TARGET, sstores(10), U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let free = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        let uncapped = exec.estimate_tx(&free, &c, StateOverrides::new()).unwrap();
        // 21000 + 10 × (3 + 3 + 22100) = 242060 gross; the buffer lifts it past 250k.
        assert!(uncapped > 250_000, "got {uncapped}");

        let mut capped = free.clone();
        capped.gas = Some(250_000);
        assert_eq!(exec.estimate_tx(&capped, &c, StateOverrides::new()).unwrap(), 250_000);

        capped.gas = Some(200_000);
        assert_eq!(
            exec.estimate_tx(&capped, &c, StateOverrides::new()).unwrap_err(),
            EvmError::GasAllowanceExceeded { allowance: 200_000 }
        );

        capped.gas = Some(20_000);
        assert_eq!(exec.estimate_tx(&capped, &c, StateOverrides::new()).unwrap(), uncapped);
    }

    /// A limit that cannot even pay the intrinsic cost is the same answer.
    #[test]
    fn estimate_tx_reports_a_ceiling_below_the_intrinsic_cost() {
        let exec = executor_with_accounts(&[(TARGET, vec![0x00], U256::ZERO, 1)]);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::from(vec![0xFF; 64]), U256::ZERO);
        tx.gas = Some(21_000);
        let err = exec.estimate_tx(&tx, &ctx(19_500_000, CANCUN_TIME + 1), StateOverrides::new()).unwrap_err();
        assert_eq!(err, EvmError::GasAllowanceExceeded { allowance: 21_000 });
        assert!(err.is_infeasible() && !err.is_refusal());
        assert_eq!(err.to_string(), "gas required exceeds allowance (21000)");
    }

    /// Out of gas at the executor's own ceiling reads the same way.
    #[test]
    fn estimate_tx_out_of_gas_at_the_default_ceiling_is_an_answer() {
        // JUMPDEST; PUSH1 0; JUMP — forever.
        let exec = executor_with_accounts(&[(TARGET, vec![0x5b, 0x60, 0x00, 0x56], U256::ZERO, 1)]);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        assert_eq!(
            exec.estimate_tx(&tx, &ctx(19_500_000, CANCUN_TIME + 1), StateOverrides::new()).unwrap_err(),
            EvmError::GasAllowanceExceeded { allowance: VIEW_CALL_GAS }
        );
    }

    /// geth's affordability cap: under a fee cap the ceiling is what the sender
    /// can pay for, and a value the sender cannot cover is refused outright.
    #[test]
    fn estimate_tx_bounds_the_ceiling_by_what_the_sender_can_pay() {
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.fees = Fees::Legacy { gas_price: 10 };

        // 1_000_000 wei at 10 wei/gas funds 100_000 gas; the work needs ~242k.
        let poor = executor_with_accounts(&[
            (SENDER, vec![], U256::from(1_000_000u64), 0),
            (TARGET, sstores(10), U256::ZERO, 1),
        ]);
        assert_eq!(
            poor.estimate_tx(&tx, &c, StateOverrides::new()).unwrap_err(),
            EvmError::GasAllowanceExceeded { allowance: 100_000 }
        );

        let funded = executor_with_accounts(&[
            (SENDER, vec![], U256::from(100_000_000u64), 0),
            (TARGET, sstores(10), U256::ZERO, 1),
        ]);
        assert!(funded.estimate_tx(&tx, &c, StateOverrides::new()).unwrap() > 242_060);

        tx.value = U256::from(100_000_000u64);
        let err = funded.estimate_tx(&tx, &c, StateOverrides::new()).unwrap_err();
        assert_eq!(err, EvmError::InsufficientFundsForTransfer);
        assert!(err.is_infeasible());
        assert_eq!(err.to_string(), "insufficient funds for transfer");
    }

    /// GASPRICE reads the request's effective price — a contract that pays a
    /// relayer `gasleft() × tx.gasprice` costs more when the price is not zero.
    #[test]
    fn estimate_tx_runs_with_the_requests_gas_price() {
        // GASPRICE; PUSH1 0; SSTORE; STOP — a zero price writes nothing new.
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10u64).pow(U256::from(18)), 0),
            (TARGET, vec![0x3a, 0x60, 0x00, 0x55, 0x00], U256::ZERO, 1),
        ]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        let free = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        tx.fees = Fees::DynamicFee { max_fee_per_gas: 10, max_priority_fee_per_gas: 1 };
        let priced = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap();
        assert!(priced > free + 15_000, "a non-zero GASPRICE stores a fresh slot: {free} → {priced}");
    }

    /// The price mapping itself: legacy `gasPrice` is the price; dynamic fees
    /// pay min(maxFee, basefee + tip); no fee field pays nothing.
    #[test]
    fn tx_env_prices_like_geth() {
        let base = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        let price = |fees: Fees, ty: Option<u8>| {
            let mut tx = base.clone();
            tx.fees = fees;
            tx.tx_type = ty;
            tx_env(&tx, 100_000, 1).unwrap().effective_gas_price(7)
        };
        assert_eq!(price(Fees::None, None), 0);
        assert_eq!(price(Fees::Legacy { gas_price: 5 }, None), 5);
        assert_eq!(price(Fees::Legacy { gas_price: 5 }, Some(TYPE_DYNAMIC_FEE)), 5);
        assert_eq!(price(Fees::DynamicFee { max_fee_per_gas: 10, max_priority_fee_per_gas: 1 }, None), 8);
        assert_eq!(price(Fees::DynamicFee { max_fee_per_gas: 7, max_priority_fee_per_gas: 3 }, None), 7);
        assert_eq!(price(Fees::None, Some(TYPE_DYNAMIC_FEE)), 0);
    }

    /// A `to`-less estimate prices a deployment: 53000 intrinsic, the EIP-3860
    /// initcode word, the constructor's run.
    #[test]
    fn estimate_tx_prices_contract_creation() {
        let exec = executor_with_accounts(&[]);
        // PUSH1 0; PUSH1 0; RETURN — deploys empty code.
        let init = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xf3]);
        let tx = TxRequest::call(SENDER, None, init, U256::ZERO);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        // 21000 + 32000 + calldata (2 zero × 4 + 3 nonzero × 16 = 56) + 1 word × 2
        // + 6 executed
        assert_eq!(lowest_limit_that_runs(&exec, &tx, &c), 53_064);
        assert_is_the_searched_estimate(&exec, &tx, &c, exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap());
    }

    /// Review regression (#509): a state-overridden balance above 2^128 with an
    /// absurd fee cap used to make `hi × price` overflow revm's u128 pricing —
    /// an `expect` panic that aborts the host. It must answer instead.
    #[test]
    fn estimate_tx_survives_a_fee_cap_that_would_overflow_revms_pricing() {
        use crate::overrides::AccountOverride;
        let exec = executor_with_accounts(&[(TARGET, vec![0x00], U256::ZERO, 1)]);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.fees = Fees::Legacy { gas_price: 1u128 << 120 };
        let mut ov = StateOverrides::new();
        ov.insert(SENDER, AccountOverride { balance: Some(U256::MAX), ..Default::default() });
        // u128::MAX / 2^120 = 255 gas: below the intrinsic cost, so geth's answer.
        assert_eq!(
            exec.estimate_tx(&tx, &ctx(19_500_000, CANCUN_TIME + 1), ov).unwrap_err(),
            EvmError::GasAllowanceExceeded { allowance: 255 }
        );
    }

    /// Review regression (#509): from Osaka no transaction may carry more than
    /// 2^24 gas (EIP-7825), so the answer is capped there — a limit above it is
    /// one the network rejects — and work beyond it is geth's allowance answer.
    #[test]
    fn estimate_tx_never_answers_above_the_osaka_transaction_cap() {
        use crate::fork::OSAKA_TIME;
        let osaka = ctx(23_900_000, OSAKA_TIME + 1);
        // 680 fresh SSTOREs: ~15.05M gross, ~17.3M buffered.
        let fits = executor_with_accounts(&[(TARGET, sstores_wide(680), U256::ZERO, 1)]);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        assert_eq!(fits.estimate_tx(&tx, &osaka, StateOverrides::new()).unwrap(), TX_GAS_LIMIT_CAP);
        // 800 of them (~17.7M) cannot fit at all.
        let too_big = executor_with_accounts(&[(TARGET, sstores_wide(800), U256::ZERO, 1)]);
        assert_eq!(
            too_big.estimate_tx(&tx, &osaka, StateOverrides::new()).unwrap_err(),
            EvmError::GasAllowanceExceeded { allowance: TX_GAS_LIMIT_CAP }
        );
        // Before Osaka the same work is simply estimated.
        let prague = too_big.estimate_tx(&tx, &prague(), StateOverrides::new()).unwrap();
        assert!(prague > TX_GAS_LIMIT_CAP, "got {prague}");
    }

    /// `n` fresh-slot SSTOREs with 2-byte slot numbers (slot i := 1), then STOP.
    fn sstores_wide(n: u16) -> Vec<u8> {
        let mut code = Vec::new();
        for slot in 0..n {
            let [hi, lo] = slot.to_be_bytes();
            code.extend_from_slice(&[0x60, 0x01, 0x61, hi, lo, 0x55]);
        }
        code.push(0x00);
        code
    }

    /// Review regression (#509): init code over EIP-3860's limit can never run —
    /// a permanent refusal, not the retryable "unavailable".
    #[test]
    fn estimate_tx_refuses_oversized_init_code() {
        let exec = executor_with_accounts(&[]);
        let tx = TxRequest::call(SENDER, None, Bytes::from(vec![0x00; 50_000]), U256::ZERO);
        let err = exec.estimate_tx(&tx, &ctx(19_500_000, CANCUN_TIME + 1), StateOverrides::new()).unwrap_err();
        assert!(err.is_refusal() && err.to_string().contains("max initcode size"), "{err:?}");
    }

    /// A refusal is decided from the request alone, by a call as by an
    /// estimate: no state is read first (the oracle below panics on any fetch).
    #[test]
    fn transaction_objects_are_refused_before_reading_state() {
        struct NoFetch;
        impl SnapStateOracle for NoFetch {
            fn fetch_account(&self, _: &[u8; 32], _: [u8; 20]) -> Result<Option<OracleAccount>, OracleError> {
                panic!("a refused request must not fetch")
            }
            fn fetch_storage(&self, _: &[u8; 32], _: [u8; 20], _: U256) -> Result<U256, OracleError> {
                panic!("a refused request must not fetch")
            }
            fn fetch_bytecode(&self, _: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
                panic!("a refused request must not fetch")
            }
        }
        let exec = EvmExecutor::new(Arc::new(NoFetch), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache));
        let refusal = |tx: &TxRequest, c: &BlockContext| {
            let estimated = exec.estimate_tx(tx, c, StateOverrides::new()).unwrap_err();
            let called = exec.call_tx(tx, c, StateOverrides::new()).unwrap_err();
            assert_eq!(estimated, called, "one refusal for both entry points");
            assert!(called.is_refusal(), "{called}");
            called.to_string()
        };
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.chain_id = Some(U256::from(5));
        assert!(refusal(&tx, &prague()).contains("does not match this node's chain"));

        let mut no_list = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        no_list.tx_type = Some(TYPE_SET_CODE);
        assert!(refusal(&no_list, &prague()).contains("requires an authorizationList"));

        let ephemeral = key(0x0b);
        let early = set_code_call(SENDER, address_of(&ephemeral), vec![sign_authorization(&ephemeral, 1, DELEGATE, 0)]);
        assert!(refusal(&early, &ctx(19_500_000, CANCUN_TIME + 1)).contains("before Prague"));
    }

    // ---- eth_call over the full transaction object (#509) -----------------

    /// Code that pushes one word with `op` and returns it.
    fn returning(op: &[u8]) -> Vec<u8> {
        let mut code = op.to_vec();
        code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
        code
    }

    fn word(out: &[u8]) -> U256 {
        U256::from_be_slice(out)
    }

    /// Wallets simulate the same 7702 transaction they then estimate: the
    /// authorization must be installed for the call too, or the call runs
    /// against an empty account and returns nothing — a well-formed answer to
    /// a different question.
    #[test]
    fn call_tx_applies_an_authorization_that_delegates_a_fresh_eoa() {
        let ephemeral = key(0x0c);
        // The delegate returns 42.
        let exec = executor_with_accounts(&[(DELEGATE, returning(&[0x60, 0x2a]), U256::ZERO, 1)]);
        let c = prague();
        let tx = set_code_call(SENDER, address_of(&ephemeral), vec![sign_authorization(&ephemeral, 1, DELEGATE, 0)]);
        assert_eq!(word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap()), U256::from(42));

        let mut dropped = tx.clone();
        dropped.tx_type = None;
        dropped.authorization_list = None;
        assert!(exec.call_tx(&dropped, &c, StateOverrides::new()).unwrap().is_empty());
    }

    /// A fee-less, limit-less transaction object is the plain call it always
    /// was, overrides included.
    #[test]
    fn call_tx_without_extended_fields_is_the_plain_call() {
        use crate::overrides::AccountOverride;
        let exec = executor_with_accounts(&[(TARGET, returning(&[0x60, 0x07]), U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        let plain = exec.call_view_from(SENDER, TARGET, &[], U256::ZERO, &c).unwrap();
        assert_eq!(exec.call_tx(&tx, &c, StateOverrides::new()).unwrap(), plain);

        let mut ov = StateOverrides::new();
        ov.insert(TARGET, AccountOverride { code: Some(returning(&[0x60, 0x09])), ..Default::default() });
        assert_eq!(word(&exec.call_tx(&tx, &c, ov).unwrap()), U256::from(9));
    }

    /// `gas` is the call's limit: running out of it is geth's "out of gas", an
    /// answer, while the same call without a limit runs.
    #[test]
    fn call_tx_runs_out_of_the_callers_gas() {
        let exec = executor_with_accounts(&[(TARGET, sstores(10), U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        assert!(exec.call_tx(&tx, &c, StateOverrides::new()).is_ok());

        tx.gas = Some(100_000);
        let err = exec.call_tx(&tx, &c, StateOverrides::new()).unwrap_err();
        assert_eq!(err, EvmError::CallOutOfGas);
        assert!(err.is_infeasible());
        assert_eq!(err.to_string(), "out of gas");
    }

    /// A limit above the executor's budget is capped there, as geth caps one at
    /// its RPC gas cap. Running dry at that cap is the executor's limit, not the
    /// caller's: refused (permanent), neither the caller's out-of-gas nor a
    /// retryable unavailable. Without a limit it stays the ordinary out-of-gas.
    #[test]
    fn call_tx_caps_the_callers_gas_at_the_budget() {
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let gas_left = executor_with_accounts(&[(TARGET, returning(&[0x5a]), U256::ZERO, 1)]);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.gas = Some(50_000_000);
        let left = word(&gas_left.call_tx(&tx, &c, StateOverrides::new()).unwrap());
        assert!(left < U256::from(VIEW_CALL_GAS - 21_000), "ran with at most the budget: {left}");

        // JUMPDEST; PUSH1 0; JUMP — spins until the gas is gone.
        let spin = executor_with_accounts(&[(TARGET, vec![0x5b, 0x60, 0x00, 0x56], U256::ZERO, 1)]);
        let capped = spin.call_tx(&tx, &c, StateOverrides::new()).unwrap_err();
        assert_eq!(capped, EvmError::CallBudgetExceeded { budget: VIEW_CALL_GAS, requested: 50_000_000 });
        assert!(capped.is_refusal());
        assert_eq!(
            capped.to_string(),
            "the call ran out of this node's 30000000-gas call budget, below the 50000000 gas it allows"
        );
        tx.gas = Some(VIEW_CALL_GAS);
        assert_eq!(spin.call_tx(&tx, &c, StateOverrides::new()).unwrap_err(), EvmError::CallOutOfGas);
        tx.gas = None;
        tx.fees = Fees::Legacy { gas_price: 7 };
        let mut funded = StateOverrides::new();
        funded.insert(SENDER, crate::overrides::AccountOverride { balance: Some(U256::MAX), ..Default::default() });
        assert_eq!(spin.call_tx(&tx, &c, funded).unwrap_err(), EvmError::OutOfGas);
    }

    /// A limit below the intrinsic cost, or below the EIP-7623 floor, is geth's
    /// answer for a call — never a run with less gas than the transaction pays.
    #[test]
    fn call_tx_refuses_a_limit_below_the_intrinsic_cost_or_the_floor() {
        let exec = executor_with_accounts(&[(TARGET, vec![0x00], U256::ZERO, 1)]);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.gas = Some(20_000);
        let err = exec.call_tx(&tx, &ctx(19_500_000, CANCUN_TIME + 1), StateOverrides::new()).unwrap_err();
        let intrinsic = EvmError::IntrinsicGasTooLow { have: 20_000, want: 21_000 };
        assert_eq!(err, EvmError::CallFailed { supplied_gas: 20_000, error: Box::new(intrinsic) });
        assert_eq!(err.to_string(), "err: intrinsic gas too low: have 20000, want 21000 (supplied gas 20000)");
        assert!(err.is_infeasible());

        // Prague: 1000 non-zero bytes cost 37000 intrinsic, but floor at 61000.
        tx.data = Bytes::from(vec![0xff; 1000]);
        tx.gas = Some(50_000);
        let err = exec.call_tx(&tx, &prague(), StateOverrides::new()).unwrap_err();
        let floor = EvmError::FloorDataGasTooLow { have: 50_000, want: 61_000 };
        assert_eq!(err, EvmError::CallFailed { supplied_gas: 50_000, error: Box::new(floor) });
        assert_eq!(
            err.to_string(),
            "err: insufficient gas for floor data gas cost: have 50000, want 61000 (supplied gas 50000)"
        );
        assert!(err.is_infeasible());
    }

    /// With a fee the sender must afford `gas × fee cap + value`, and the run
    /// sees it debited `gas × effective price` — geth's buyGas. Fee-less, the
    /// balance is untouched, as a call without a transaction object always was.
    #[test]
    fn call_tx_charges_the_sender_for_its_fee() {
        // BALANCE(CALLER), returned.
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10_000_000u64), 0),
            (TARGET, returning(&[0x33, 0x31]), U256::ZERO, 1),
        ]);
        let c = ctx(19_500_000, CANCUN_TIME + 1); // base fee 7
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        assert_eq!(word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap()), U256::from(10_000_000u64));

        // Effective price min(10, 7 + 1) = 8 on a 100k limit.
        tx.gas = Some(100_000);
        tx.fees = Fees::DynamicFee { max_fee_per_gas: 10, max_priority_fee_per_gas: 1 };
        assert_eq!(
            word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap()),
            U256::from(10_000_000u64 - 800_000)
        );

        // 100k × 10 + 9.1M = 10.1M > 10M.
        tx.value = U256::from(9_100_000u64);
        let err = exec.call_tx(&tx, &c, StateOverrides::new()).unwrap_err();
        let short = EvmError::InsufficientFunds {
            address: SENDER,
            have: U256::from(10_000_000u64),
            want: U256::from(10_100_000u64),
        };
        assert_eq!(err, EvmError::CallFailed { supplied_gas: 100_000, error: Box::new(short) });
        assert_eq!(
            err.to_string(),
            "err: insufficient funds for gas * price + value: address \
             0x4242424242424242424242424242424242424242 have 10000000 want 10100000 (supplied gas 100000)"
        );
        assert!(err.is_infeasible());
    }

    /// geth's buyGas holds for a fee-less call too: moving more than the
    /// sender holds is refused as the chain would refuse it — never run
    /// against a balance the sender does not have — while a call that moves
    /// nothing needs no balance at all.
    #[test]
    fn call_tx_refuses_a_value_the_sender_cannot_cover_even_without_a_fee() {
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(1_000u64), 0),
            (TARGET, vec![0x00], U256::ZERO, 1),
        ]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::from(1_001u64));
        tx.gas = Some(100_000);
        let err = exec.call_tx(&tx, &c, StateOverrides::new()).unwrap_err();
        let short = EvmError::InsufficientFunds { address: SENDER, have: U256::from(1_000u64), want: U256::from(1_001u64) };
        assert_eq!(err, EvmError::CallFailed { supplied_gas: 100_000, error: Box::new(short) });

        tx.value = U256::from(1_000u64);
        assert!(exec.call_tx(&tx, &c, StateOverrides::new()).unwrap().is_empty());
        // An empty account can still make a call that moves nothing.
        let mut broke = TxRequest::call([0x77; 20], Some(TARGET), Bytes::new(), U256::ZERO);
        broke.gas = Some(100_000);
        assert!(exec.call_tx(&broke, &c, StateOverrides::new()).unwrap().is_empty());
    }

    /// A price revm cannot represent is answered, never run: revm `expect`s
    /// `gas × price + value` to fit, and with its balance check off a panic
    /// there aborts the host process.
    #[test]
    fn call_tx_answers_a_price_revm_cannot_represent() {
        use crate::overrides::AccountOverride;
        let exec = executor_with_accounts(&[(TARGET, vec![0x00], U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let rich = || {
            let mut ov = StateOverrides::new();
            ov.insert(SENDER, AccountOverride { balance: Some(U256::MAX), ..Default::default() });
            ov
        };
        // gas × fee + value past 2^256: geth's own refusal.
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::MAX);
        tx.gas = Some(21_000);
        tx.fees = Fees::Legacy { gas_price: 7 };
        let err = exec.call_tx(&tx, &c, rich()).unwrap_err();
        assert_eq!(
            err,
            EvmError::CallFailed { supplied_gas: 21_000, error: Box::new(EvmError::RequiredBalanceOverflow { address: SENDER }) }
        );
        assert_eq!(
            err.to_string(),
            "err: insufficient funds for gas * price + value: address \
             0x4242424242424242424242424242424242424242 required balance exceeds 256 bits (supplied gas 21000)"
        );
        // gas × fee past 2^128 against an overridden fortune: refused as a
        // price this engine cannot run.
        tx.value = U256::ZERO;
        tx.fees = Fees::Legacy { gas_price: u128::MAX };
        assert!(matches!(exec.call_tx(&tx, &c, rich()).unwrap_err(), EvmError::InvalidRequest { .. }));
    }

    /// A request that contradicts itself is refused before any check of what
    /// it could afford — for a call exactly as for an estimate.
    #[test]
    fn call_tx_refuses_a_contradictory_nonce_before_the_fee_checks() {
        use crate::overrides::AccountOverride;
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10u64).pow(U256::from(18)), 0),
            (TARGET, vec![0x00], U256::ZERO, 1),
        ]);
        let c = ctx(19_500_000, CANCUN_TIME + 1); // base fee 7
        let overrides = || {
            let mut ov = StateOverrides::new();
            ov.insert(SENDER, AccountOverride { nonce: Some(5), ..Default::default() });
            ov
        };
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.nonce = Some(6);
        tx.fees = Fees::Legacy { gas_price: 1 }; // below the base fee
        let call = exec.call_tx(&tx, &c, overrides()).unwrap_err();
        assert!(matches!(call, EvmError::InvalidRequest { .. }), "{call:?}");
        assert_eq!(call, exec.estimate_tx(&tx, &c, overrides()).unwrap_err());
    }

    /// A plain call whose calldata alone costs more than the budget is geth's
    /// answer for a call at its gas cap — infeasible, worded as geth's eth_call
    /// words it — not a call this node cannot serve right now.
    #[test]
    fn a_plain_call_whose_calldata_outweighs_the_budget_is_geths_answer() {
        let exec = executor_with_accounts(&[(TARGET, vec![0x00], U256::ZERO, 1)]);
        // Prague: 800k non-zero bytes floor at 21000 + 40 × 800000 = 32.021 M.
        let data = vec![0xff; 800_000];
        let err = exec.call_view_from(SENDER, TARGET, &data, U256::ZERO, &prague()).unwrap_err();
        let floor = EvmError::FloorDataGasTooLow { have: VIEW_CALL_GAS, want: 32_021_000 };
        assert_eq!(err, EvmError::CallFailed { supplied_gas: VIEW_CALL_GAS, error: Box::new(floor) });
        assert!(err.is_infeasible());
    }

    /// GASPRICE reads the effective price in a call, as in an estimate.
    #[test]
    fn call_tx_runs_with_the_requests_gas_price() {
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10u64).pow(U256::from(18)), 0),
            (TARGET, returning(&[0x3a]), U256::ZERO, 1),
        ]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        assert_eq!(word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap()), U256::ZERO);
        tx.fees = Fees::DynamicFee { max_fee_per_gas: 10, max_priority_fee_per_gas: 1 };
        assert_eq!(word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap()), U256::from(8));
    }

    /// The access list is charged (2400 + 1900 intrinsic) and pre-warms its
    /// slot: GAS after reading that slot shows both.
    #[test]
    fn call_tx_charges_and_prewarms_the_access_list() {
        // PUSH1 0; SLOAD; POP; GAS — returned.
        let exec = executor_with_accounts(&[(TARGET, returning(&[0x60, 0x00, 0x54, 0x50, 0x5a]), U256::ZERO, 1)]);
        let c = ctx(19_500_000, CANCUN_TIME + 1);
        let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
        tx.gas = Some(100_000);
        let cold = word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap());
        tx.access_list = Some(vec![AccessListItem { address: TARGET, storage_keys: vec![[0u8; 32]] }]);
        let warm = word(&exec.call_tx(&tx, &c, StateOverrides::new()).unwrap());
        // 4300 more up front, 2000 less for the warm read.
        assert_eq!(cold - warm, U256::from(2_300u64));
    }

    /// A fee cap below the block's base fee names a transaction no block at
    /// this base fee includes: geth answers so for a call and for an estimate.
    #[test]
    fn a_fee_cap_below_the_base_fee_is_refused_for_calls_and_estimates() {
        let exec = executor_with_accounts(&[
            (SENDER, vec![], U256::from(10u64).pow(U256::from(18)), 0),
            (TARGET, vec![0x00], U256::ZERO, 1),
        ]);
        let c = ctx(19_500_000, CANCUN_TIME + 1); // base fee 7
        for (fees, fee_cap) in [
            (Fees::Legacy { gas_price: 5 }, 5u128),
            (Fees::DynamicFee { max_fee_per_gas: 6, max_priority_fee_per_gas: 1 }, 6),
        ] {
            let mut tx = TxRequest::call(SENDER, Some(TARGET), Bytes::new(), U256::ZERO);
            tx.fees = fees;
            let want = EvmError::FeeCapTooLow { address: SENDER, fee_cap, base_fee: 7 };
            let call = exec.call_tx(&tx, &c, StateOverrides::new()).unwrap_err();
            assert_eq!(call, EvmError::CallFailed { supplied_gas: VIEW_CALL_GAS, error: Box::new(want.clone()) });
            assert_eq!(call.to_string(), format!("err: {want} (supplied gas {VIEW_CALL_GAS})"));
            assert!(want.is_infeasible());
            assert_eq!(
                want.to_string(),
                format!(
                    "max fee per gas less than block base fee: address \
                     0x4242424242424242424242424242424242424242, maxFeePerGas: {fee_cap}, baseFee: 7"
                )
            );
            // The estimate reports it as geth's estimator does: with the ceiling
            // the refused run was made at.
            let estimate = exec.estimate_tx(&tx, &c, StateOverrides::new()).unwrap_err();
            assert_eq!(estimate, EvmError::FailedWithGas { gas: VIEW_CALL_GAS, error: Box::new(want.clone()) });
            assert!(estimate.is_infeasible());
            assert_eq!(estimate.to_string(), format!("failed with {VIEW_CALL_GAS} gas: {want}"));
        }
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

    /// Sepolia's first Amsterdam slot (ethereum/pm#2205).
    const SEPOLIA_AMSTERDAM_SLOT: u64 = 11_296_768;

    /// A sepolia context at `ts` (the one chain with an Amsterdam date). Like a
    /// real header, it carries a slot number only from Amsterdam on.
    fn sepolia_ctx(ts: u64) -> BlockContext {
        let mut c = ctx(10_000_000, ts);
        c.chain_id = 11_155_111;
        c.slot_number =
            (ts >= crate::fork::SEPOLIA_AMSTERDAM_TIME).then_some(SEPOLIA_AMSTERDAM_SLOT);
        c
    }

    /// Every fetch panics: proves a refusal happens before any state is read.
    struct NoFetchOracle;
    impl SnapStateOracle for NoFetchOracle {
        fn fetch_account(
            &self,
            _: &[u8; 32],
            _: [u8; 20],
        ) -> Result<Option<OracleAccount>, OracleError> {
            panic!("a refused context must not fetch")
        }
        fn fetch_storage(&self, _: &[u8; 32], _: [u8; 20], _: U256) -> Result<U256, OracleError> {
            panic!("a refused context must not fetch")
        }
        fn fetch_bytecode(&self, _: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
            panic!("a refused context must not fetch")
        }
    }

    /// SLOTNUM PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — returns the slot.
    const SLOTNUM_CODE: [u8; 9] = [0x4b, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

    #[test]
    fn slotnum_returns_the_headers_slot_on_amsterdam() {
        let exec = executor_with(SLOTNUM_CODE.to_vec(), None);
        let mut c = sepolia_ctx(crate::fork::SEPOLIA_AMSTERDAM_TIME);
        let out = exec
            .call_view(TARGET, &[], &c)
            .expect("SLOTNUM runs on Amsterdam");
        assert_eq!(
            U256::from_be_slice(&out),
            U256::from(SEPOLIA_AMSTERDAM_SLOT)
        );
        // It is the context's slot, not a constant: a later block reads its own.
        c.slot_number = Some(SEPOLIA_AMSTERDAM_SLOT + 5);
        let out = exec.call_view(TARGET, &[], &c).unwrap();
        assert_eq!(
            U256::from_be_slice(&out),
            U256::from(SEPOLIA_AMSTERDAM_SLOT + 5)
        );
    }

    #[test]
    fn amsterdam_context_without_a_slot_is_refused_before_any_fetch() {
        // Never SLOTNUM against a made-up 0: a verified Amsterdam header always
        // carries the slot, so its absence means the block isn't what the fork
        // table says — refused for good, and before the peers are asked anything.
        let exec = EvmExecutor::new(
            Arc::new(NoFetchOracle),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let mut c = sepolia_ctx(crate::fork::SEPOLIA_AMSTERDAM_TIME);
        c.slot_number = None;
        let refused = |r: Result<(), EvmError>| {
            let e = r.unwrap_err();
            assert!(
                matches!(
                    e,
                    EvmError::MissingSlotNumber {
                        block_number: 10_000_000
                    }
                ),
                "{e:?}"
            );
            assert!(e.is_refusal(), "a missing slot is permanent: {e:?}");
        };
        refused(exec.call_view(TARGET, &[], &c).map(drop));
        refused(
            exec.create_view(
                [0u8; 20],
                &SLOTNUM_CODE,
                U256::ZERO,
                &c,
                StateOverrides::new(),
            )
            .map(drop),
        );
        refused(
            exec.estimate_gas([0x42; 20], TARGET, &[], U256::from(1u64), &c)
                .map(drop),
        );
    }

    #[test]
    fn a_slot_before_amsterdam_is_refused_before_any_fetch() {
        // A slot number in the header means an Amsterdam block. If the fork
        // table disagrees — no Amsterdam date (mainnet), or a later one — the
        // network moved the fork after this build shipped: refused for good
        // rather than answered under the older fork's opcodes and gas.
        let exec = EvmExecutor::new(
            Arc::new(NoFetchOracle),
            Arc::new(NoopStateProofCache),
            Arc::new(NoopBytecodeCache),
        );
        let mut before = sepolia_ctx(crate::fork::SEPOLIA_AMSTERDAM_TIME - 1);
        before.slot_number = Some(SEPOLIA_AMSTERDAM_SLOT - 1);
        let mut mainnet = ctx(10_000_000, crate::fork::SEPOLIA_AMSTERDAM_TIME + 1);
        mainnet.slot_number = Some(1);
        for c in [before, mainnet] {
            let refused = |r: Result<(), EvmError>| {
                let e = r.unwrap_err();
                assert!(
                    matches!(
                        e,
                        EvmError::UnexpectedSlotNumber {
                            block_number: 10_000_000
                        }
                    ),
                    "{e:?}"
                );
                assert!(
                    e.is_refusal(),
                    "an unscheduled Amsterdam block is permanent: {e:?}"
                );
            };
            refused(exec.call_view(TARGET, &[], &c).map(drop));
            refused(
                exec.create_view(
                    [0u8; 20],
                    &SLOTNUM_CODE,
                    U256::ZERO,
                    &c,
                    StateOverrides::new(),
                )
                .map(drop),
            );
            refused(
                exec.estimate_gas([0x42; 20], TARGET, &[], U256::from(1u64), &c)
                    .map(drop),
            );
        }
    }

    #[test]
    fn slotnum_is_invalid_before_amsterdam_and_needs_no_slot() {
        // One second before activation there is no slot in the header and
        // nothing to refuse — the context runs, and SLOTNUM itself is simply an
        // invalid opcode there (revm gates it on AMSTERDAM).
        let c = sepolia_ctx(crate::fork::SEPOLIA_AMSTERDAM_TIME - 1);
        assert_eq!(c.slot_number, None);
        let chain_id = executor_with(
            vec![0x46u8, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3],
            None,
        )
        .call_view(TARGET, &[], &c)
        .expect("a pre-Amsterdam context needs no slot");
        assert_eq!(U256::from_be_slice(&chain_id), U256::from(11_155_111u64));
        let err = executor_with(SLOTNUM_CODE.to_vec(), None)
            .call_view(TARGET, &[], &c)
            .unwrap_err();
        assert!(matches!(err, EvmError::Halted { .. }), "got {err:?}");
    }

    #[test]
    fn amsterdam_gas_model_is_enabled_only_for_amsterdam() {
        let sepolia = 11_155_111u64;
        for spec in [
            SpecId::LONDON,
            SpecId::CANCUN,
            SpecId::PRAGUE,
            SpecId::OSAKA,
        ] {
            let cfg = view_cfg(spec, sepolia);
            assert!(
                !cfg.enable_amsterdam_eip8037,
                "{spec:?} must not run EIP-8037 state gas"
            );
            assert!(
                !cfg.enable_amsterdam_eip2780,
                "{spec:?} must not run EIP-2780 intrinsic gas"
            );
        }
        let cfg = view_cfg(SpecId::AMSTERDAM, sepolia);
        assert!(
            cfg.enable_amsterdam_eip8037,
            "AMSTERDAM runs EIP-8037 state gas"
        );
        assert!(
            cfg.enable_amsterdam_eip2780,
            "AMSTERDAM runs EIP-2780 intrinsic gas"
        );
        // reth leaves revm's two Amsterdam opt-outs alone (EIP-7708 transfer logs
        // and EIP-8246 self-destruct clearing stay active); so do we.
        assert!(!cfg.amsterdam_eip7708_disabled);
        assert!(!cfg.amsterdam_eip8246_delayed_clear_disabled);
        // The view-call relaxations are fork-independent.
        assert_eq!(cfg.tx_gas_limit_cap, Some(VIEW_CALL_GAS));
        assert_eq!(cfg.chain_id, sepolia);
    }

    #[test]
    fn amsterdam_call_runs_on_the_amsterdam_rung() {
        // CHAINID PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN at the activation
        // instant: the envelope passes EIP-2780/EIP-8037 validation with the
        // view-call gas settings, and the answer comes from the right chain.
        let code = vec![0x46u8, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let exec = executor_with(code, None);
        let c = sepolia_ctx(crate::fork::SEPOLIA_AMSTERDAM_TIME);
        let out = exec
            .call_view(TARGET, &[], &c)
            .expect("amsterdam call must run");
        assert_eq!(U256::from_be_slice(&out), U256::from(11_155_111u64));
    }

    #[test]
    fn amsterdam_value_transfer_to_an_empty_account_is_metered_not_21000() {
        // EIP-2780 charges a value transfer to an EMPTY account EIP-8037
        // account-creation state gas on top of its intrinsic, so the pre-Amsterdam
        // 21000 short-circuit would under-estimate it ~10x and the tx would OOG.
        // TARGET is proven absent; the sender covers the value it moves.
        let fx = FixtureSnapStateOracle::new().with_account(
            ROOT,
            [0x42; 20],
            OracleAccount {
                nonce: 1,
                balance: U256::from(1u64),
                code_hash: myotis_core::trie::EMPTY_CODE_HASH,
                storage_root: [0x9; 32],
            },
        );
        let exec = EvmExecutor::new(Arc::new(fx), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache));
        let t = crate::fork::SEPOLIA_AMSTERDAM_TIME;
        // One second before activation (Osaka) the exact answer is unchanged.
        let osaka = exec
            .estimate_gas(
                [0x42; 20],
                TARGET,
                &[],
                U256::from(1u64),
                &sepolia_ctx(t - 1),
            )
            .unwrap();
        assert_eq!(osaka, 21_000);
        let amsterdam = exec
            .estimate_gas([0x42; 20], TARGET, &[], U256::from(1u64), &sepolia_ctx(t))
            .unwrap();
        let state_gas = view_cfg(SpecId::AMSTERDAM, 11_155_111)
            .gas_params
            .new_account_state_gas();
        assert!(state_gas > 0, "Amsterdam must price new-account state gas");
        assert!(
            amsterdam > 21_000 && amsterdam >= state_gas,
            "estimate {amsterdam} must cover the {state_gas} new-account state gas"
        );
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
