package io.myotis.evm;

import com.jaeckel.ethp2p.core.concurrent.Futures;
import io.myotis.evm.besu.BlockContextValues;
import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.world.AccessTracker;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.SnapStateOracle;
import io.myotis.evm.world.SnapWorldUpdater;
import io.myotis.evm.world.SyncStateView;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.frame.ExceptionalHaltReason;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.processor.MessageCallProcessor;
import org.hyperledger.besu.evm.tracing.OperationTracer;

import java.util.Deque;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Default {@link EvmExecutor} implementation. Orchestrates Besu's EVM against
 * a {@link SnapStateOracle}, with optional CCIP-Read handling on top.
 *
 * <p>Phase 0 status: synchronous {@code callView} backed by a fixture oracle
 * works end-to-end. Prefetch loop and CCIP-Read handler are not wired here
 * yet — they live in their own packages and will plug in via Phase 2 / Phase 4.
 */
public final class DefaultEvmExecutor implements EvmExecutor {

    /** Sender for view calls; matches Geth's default. */
    private static final io.myotis.evm.Address VIEW_CALLER =
            io.myotis.evm.Address.ZERO;

    /** Cap on the gas a single view call may consume. */
    private static final long DEFAULT_GAS_LIMIT = 30_000_000L;

    private final SnapStateOracle oracle;
    private final BytecodeCache bytecodeCache;
    private final Executor executor;

    public DefaultEvmExecutor(SnapStateOracle oracle, BytecodeCache bytecodeCache, Executor executor) {
        this.oracle = oracle;
        this.bytecodeCache = bytecodeCache;
        this.executor = executor;
    }

    /**
     * Convenience constructor for tests and Phase 0 integration. <strong>Uses
     * an inline executor</strong> ({@code Runnable::run}), so the returned
     * future is effectively synchronous and any blocking inside execution
     * (Phase 1+ {@code SyncStateView.join()} on real SNAP fetches) blocks the
     * calling thread. Production callers must use the three-arg constructor
     * with a worker thread pool — typically the same pool used by the rest of
     * the wallet — to avoid stalling the UI / coroutine context. Documented
     * at the boundary because the wallet integration owns the lifecycle.
     */
    public DefaultEvmExecutor(SnapStateOracle oracle) {
        this(oracle, BytecodeCache.inMemory(), Runnable::run);
    }

    @Override
    public CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext) {
        return callView(null, target, calldata, null, blockContext);
    }

    @Override
    public CompletableFuture<byte[]> callView(Address sender, Address target, byte[] calldata,
                                              java.math.BigInteger value, BlockContext blockContext) {
        return CompletableFuture.supplyAsync(
                () -> runOnce(sender, target, calldata, value, blockContext), executor);
    }

    @Override
    public CompletableFuture<Long> estimateGas(UnsignedTransaction tx, BlockContext blockContext) {
        if (tx.to() == null) {
            return Futures.failedFuture(new UnsupportedOperationException(
                    "Phase 5 does not yet handle contract creation (to=null)"));
        }
        return CompletableFuture.supplyAsync(() -> estimateGasOnce(tx, blockContext), executor);
    }

    private long estimateGasOnce(UnsignedTransaction tx, BlockContext blockContext) {
        CryptoProviders.ensureRegistered();
        long intrinsicGas = computeIntrinsicGas(tx.data());
        long ceiling = estimateCeiling(tx, blockContext, () -> balanceOf(tx.from(), blockContext));
        // EIP-7623: from Prague on a transaction is charged at least this floor,
        // so the answer must cover it (the Rust estimate's `tx_gas_used` twin).
        long floor = EvmFactory.calldataFloorActive(blockContext) ? computeCalldataFloor(tx.data()) : 0L;
        if (intrinsicGas > ceiling || floor > ceiling) {
            // The limit does not even cover the intrinsic cost (or the floor).
            // Note: a frame budget of exactly 0 is legal — a plain ETH transfer
            // to an existing EOA at gasLimit=21000 has no EVM execution.
            throw new EvmExecutionException(new EvmExecutionError.GasAllowanceExceeded(ceiling));
        }
        // One EVM and one view for every run below: the search's probes reuse the
        // EVM's code analysis and read the state the first run fetched.
        EvmFactory.EvmAndPrecompiles bundle = EvmFactory.buildForBlock(blockContext);
        SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, new AccessTracker());
        MessageFrame first = runPlanned(bundle, estimatePlan(tx, blockContext, ceiling, intrinsicGas),
                blockContext, view, OperationTracer.NO_TRACING);
        if (first.getState() != MessageFrame.State.COMPLETED_SUCCESS) {
            // Out of gas AT the ceiling: more than the caller allowed.
            throw failureOf(first, new EvmExecutionError.GasAllowanceExceeded(ceiling));
        }
        // geth's search, from the most the run at the ceiling drew (at least the
        // floor: its MaxUsedGas).
        long drawn = Math.max(ceiling - first.getRemainingGas(), floor);
        long lowest = lowestWorkingLimit(bundle, tx, blockContext, view, intrinsicGas, floor, drawn, ceiling);
        // 15% safety buffer over the lowest limit that works. A slightly-too-high
        // estimate just costs the user some priority fee; a slightly-too-low one
        // OOG's the broadcast transaction — so round *up* strictly. Math.round
        // can round down (e.g. for totals where total * 1.15 lands just below
        // x.5), defeating the safety property. Never above the ceiling: the run
        // just succeeded AT it, so the ceiling is itself a limit that works —
        // geth's invariant.
        return Math.min((long) Math.ceil(lowest * 1.15), ceiling);
    }

    /**
     * An estimate's ceiling — geth's {@code hi} (#509) — or geth's refusal before
     * any run: the executor's budget and EIP-7825's cap from Osaka, lowered by the
     * caller's {@code gas} (from 21000; without one, by the block's gas limit,
     * where geth's search starts) and, under a fee cap, by what the sender can pay
     * for; then a fee cap below the base fee, and geth's buyGas at that ceiling —
     * without a fee, the value the sender moves. The answer never exceeds it, and
     * a transaction that does not succeed within it is geth's "gas required
     * exceeds allowance". {@code balance} supplies the sender's verified balance,
     * asked at most once and only when a rule needs it. ONE copy for the metered
     * estimate and the JSON-RPC backend's plain-transfer short-circuit, so a rule
     * cannot reach one and not the other.
     *
     * @throws EvmExecutionException carrying the refusal, an
     *         {@link EvmExecutionError.Infeasible}
     */
    public static long estimateCeiling(UnsignedTransaction tx, BlockContext blockContext,
                                       java.util.function.Supplier<java.math.BigInteger> balance) {
        java.math.BigInteger[] known = new java.math.BigInteger[1];
        java.util.function.Supplier<java.math.BigInteger> once =
                () -> known[0] != null ? known[0] : (known[0] = balance.get());
        long ceiling = Math.min(DEFAULT_GAS_LIMIT, EvmFactory.txGasLimitCap(blockContext));
        if (tx.gasLimit() != null && tx.gasLimit() >= 21_000L) {
            // Below 21000 geth reads a gas limit as none, and so do we.
            ceiling = Math.min(ceiling, tx.gasLimit());
        } else if (blockContext.gasLimit() > 0) {
            // No block holds a larger transaction.
            ceiling = Math.min(ceiling, blockContext.gasLimit());
        }
        java.math.BigInteger feeCap = tx.feeCapOrZero();
        if (feeCap.signum() > 0) {
            java.math.BigInteger have = once.get();
            if (tx.value().compareTo(have) >= 0) {
                throw new EvmExecutionException(new EvmExecutionError.InsufficientFundsForTransfer());
            }
            java.math.BigInteger fundable = have.subtract(tx.value()).divide(feeCap);
            if (fundable.compareTo(java.math.BigInteger.valueOf(ceiling)) < 0) {
                ceiling = fundable.longValue();
            }
        }
        // geth checks the fee cap against the base fee when it first RUNS the
        // transaction — after the affordability checks above, before the
        // intrinsic cost is weighed against the ceiling (the Rust estimate's
        // order) — then its buyGas; its estimator reports that run's refusal
        // with the ceiling it ran at.
        EvmExecutionError.FeeCapTooLow feeCapTooLow = feeCapBelowBaseFee(tx, blockContext);
        if (feeCapTooLow != null) {
            throw new EvmExecutionException(new EvmExecutionError.FailedWithGas(ceiling, feeCapTooLow));
        }
        EvmExecutionError.Infeasible shortfall = buyGasShortfall(tx, ceiling, once);
        if (shortfall != null) {
            throw new EvmExecutionException(new EvmExecutionError.FailedWithGas(ceiling, shortfall));
        }
        return ceiling;
    }

    /**
     * geth's buyGas: the sender must hold {@code gasLimit × fee cap + value}, a
     * sum that must fit 256 bits — the shortfall as geth's error, or null.
     * {@code balance} is asked only when something is owed. ONE copy for a call
     * and an estimate (the Rust {@code buy_gas_shortfall} twin).
     */
    static EvmExecutionError.Infeasible buyGasShortfall(UnsignedTransaction tx, long gasLimit,
                                                        java.util.function.Supplier<java.math.BigInteger> balance) {
        java.math.BigInteger want = java.math.BigInteger.valueOf(gasLimit).multiply(tx.feeCapOrZero()).add(tx.value());
        if (want.bitLength() > 256) {
            return new EvmExecutionError.RequiredBalanceOverflow(tx.from());
        }
        if (want.signum() == 0) {
            return null;
        }
        java.math.BigInteger have = balance.get();
        return have.compareTo(want) < 0 ? new EvmExecutionError.InsufficientFunds(tx.from(), have, want) : null;
    }

    /** The gas a value-bearing CALL hands its callee on top (geth's
     *  {@code params.CallStipend}): geth's first probe adds it to the draw. */
    private static final long CALL_STIPEND = 2_300;
    /** How long the search may keep bisecting before the limit in hand — one
     *  that works — is the answer. An abandoned JSON-RPC wait does not stop an
     *  estimate on this engine, so this bounds how long one holds an EVM thread
     *  (the Rust engine cancels instead). */
    private static final long SEARCH_BUDGET_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
    /** geth's {@code estimateGasErrorRatio}: the search stops within 1.5% of the
     *  lowest limit that works — the 1.15 buffer on top dwarfs it. */
    private static final double ESTIMATE_ERROR_RATIO = 0.015;

    /**
     * geth's estimator search ({@code eth/gasestimator}) for the lowest gas
     * limit at which {@code tx} succeeds, given a run at {@code hi} that
     * succeeded having drawn {@code drawn}: a first probe tries what it drew plus
     * the call stipend with the 63/64 a nested call withholds — usually the
     * answer — and bisection, skewed low, stops within
     * {@link #ESTIMATE_ERROR_RATIO} of it (or at {@link #SEARCH_BUDGET_NANOS},
     * with the working limit in hand). A probe that fails for any reason (out of
     * gas, a revert, a halt, a limit below the intrinsic cost or the floor)
     * raises the limit; an error reading state ends the search with it. The Rust
     * estimate's {@code lowest_working_limit} twin, down to the one deliberate
     * difference from geth: geth searches down to what the run was charged
     * (after refunds), this search stops at what it drew. Below that a limit can
     * only "work" by running a different transaction — a failure caught deep
     * inside (try/catch, a multicall that tolerates one), a {@code gasleft()}
     * branch — which is not the one the caller simulated. A probe cannot tell a
     * caught failure from success, though, so above the draw the search finds
     * the lowest limit at which the OUTER transaction succeeds: a call whose
     * failure is caught d levels down needs (64/63)^d of what it drew, which
     * the 1.15 buffer covers through d = 8, not from d = 9 on.
     */
    private long lowestWorkingLimit(EvmFactory.EvmAndPrecompiles bundle, UnsignedTransaction tx,
                                    BlockContext blockContext, SyncStateView view, long intrinsicGas, long floor,
                                    long drawn, long hi) {
        long deadline = System.nanoTime() + SEARCH_BUDGET_NANOS;
        long lo = drawn - 1;
        long optimistic = (drawn + CALL_STIPEND) * 64 / 63;
        if (optimistic < hi) {
            if (succeedsWith(bundle, tx, blockContext, view, intrinsicGas, floor, optimistic)) {
                hi = optimistic;
            } else {
                lo = optimistic;
            }
        }
        while (lo + 1 < hi && System.nanoTime() - deadline < 0) {
            // Within the error ratio of the answer: a wallet bumps the limit
            // anyway, and every probe is a full run.
            if ((double) (hi - lo) / hi < ESTIMATE_ERROR_RATIO) {
                break;
            }
            // Skewed low: most transactions need little more than they drew.
            long mid = Math.min((hi + lo) / 2, lo * 2);
            if (succeedsWith(bundle, tx, blockContext, view, intrinsicGas, floor, mid)) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        return hi;
    }

    /** Whether {@code tx} succeeds with {@code gasLimit} — one probe of
     *  {@link #lowestWorkingLimit}. Below the intrinsic cost or the floor it
     *  cannot, and geth's estimator raises the limit on that. */
    private boolean succeedsWith(EvmFactory.EvmAndPrecompiles bundle, UnsignedTransaction tx,
                                 BlockContext blockContext, SyncStateView view, long intrinsicGas, long floor,
                                 long gasLimit) {
        if (gasLimit < intrinsicGas || gasLimit < floor) {
            return false;
        }
        return runPlanned(bundle, estimatePlan(tx, blockContext, gasLimit, intrinsicGas), blockContext, view,
                OperationTracer.NO_TRACING).getState() == MessageFrame.State.COMPLETED_SUCCESS;
    }

    /** What one run of {@code tx} at {@code gasLimit} draws, gross — the base a
     *  single-run estimate buffered. Package-private as a test seam: tests show
     *  where that base is not a limit that works and the search is. */
    long drawnAt(UnsignedTransaction tx, BlockContext blockContext, long gasLimit) {
        long intrinsicGas = computeIntrinsicGas(tx.data());
        SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, new AccessTracker());
        MessageFrame frame = runPlanned(EvmFactory.buildForBlock(blockContext),
                estimatePlan(tx, blockContext, gasLimit, intrinsicGas), blockContext, view, OperationTracer.NO_TRACING);
        return gasLimit - frame.getRemainingGas();
    }

    /** The estimate's run of {@code tx} at {@code gasLimit}: priced and debited
     *  as the transaction would be (geth runs its estimate through the same
     *  state transition as a call). */
    private static CallPlan estimatePlan(UnsignedTransaction tx, BlockContext blockContext, long gasLimit,
                                         long intrinsicGas) {
        return new CallPlan(tx.from(), tx.to(), tx.data(), tx.value(), gasLimit, gasLimit - intrinsicGas,
                Wei.of(tx.effectiveGasPrice(blockContext.baseFeePerGas())), gasLimit);
    }

    /**
     * {@code eth_call} for a transaction object (#509): {@code gas} is the call's
     * limit (capped at the executor's budget, as geth caps it at its RPC gas cap),
     * and a fee must reach the block's base fee, is affordable by the sender and
     * is debited from it before the call runs, with GASPRICE reading the
     * effective price — geth's {@code eth_call}. Contract creation is not served.
     */
    @Override
    public CompletableFuture<byte[]> callTx(UnsignedTransaction tx, BlockContext blockContext) {
        if (tx.to() == null) {
            return Futures.failedFuture(new UnsupportedOperationException(
                    "this engine does not run contract creation (to=null)"));
        }
        return CompletableFuture.supplyAsync(() -> {
            CallPlan plan = planCall(tx, blockContext);
            SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, new AccessTracker());
            return runPlannedOnTracedView(plan, blockContext, view, OperationTracer.NO_TRACING);
        }, executor);
    }

    /**
     * What one call runs with, decided — and refused — before any EVM run: the
     * sender and target, the transaction's gas limit and the frame's share of it
     * after the intrinsic cost, the effective price GASPRICE reads and the sender
     * is debited at, and the gas the caller set, if any — running out of it is
     * the caller's answer, geth's "out of gas", unless it was above the budget
     * and capped ({@link #outOfGas}).
     */
    record CallPlan(io.myotis.evm.Address sender, io.myotis.evm.Address target, byte[] data,
                    java.math.BigInteger value, long gasLimit, long frameGas, Wei price,
                    Long callerGas) {}

    /** The plan a plain view call has always run with: the whole budget handed to
     *  the frame, no price, no debit. */
    static CallPlan viewPlan(io.myotis.evm.Address sender, io.myotis.evm.Address target, byte[] calldata,
                             java.math.BigInteger value) {
        return new CallPlan(sender != null ? sender : VIEW_CALLER, target, calldata,
                value != null ? value : java.math.BigInteger.ZERO,
                DEFAULT_GAS_LIMIT, DEFAULT_GAS_LIMIT, Wei.ZERO, null);
    }

    /**
     * Decide a transaction-object call's plan, in geth's order: the fee cap
     * against the base fee, the balance against {@code gas × fee cap + value}
     * (fee or not — geth's {@code buyGas}), then the limit against the
     * intrinsic cost and the EIP-7623 floor. Each failure is geth's answer
     * ({@link EvmExecutionError.FeeCapTooLow},
     * {@link EvmExecutionError.RequiredBalanceOverflow},
     * {@link EvmExecutionError.InsufficientFunds},
     * {@link EvmExecutionError.IntrinsicGasTooLow},
     * {@link EvmExecutionError.FloorDataGasTooLow}) wrapped as geth's
     * {@code eth_call} wraps it ({@link EvmExecutionError.CallFailed}), thrown
     * as {@link EvmExecutionException}.
     */
    CallPlan planCall(UnsignedTransaction tx, BlockContext blockContext) {
        // Fork validation first (the Rust call_tx's spec_for-before-checks twin):
        // a block no run would serve must not cost the balance read below.
        EvmFactory.requireSupported(blockContext);
        CryptoProviders.ensureRegistered();
        long gasLimit = tx.gasLimit() == null ? DEFAULT_GAS_LIMIT : Math.min(tx.gasLimit(), DEFAULT_GAS_LIMIT);
        EvmExecutionError.FeeCapTooLow feeCapTooLow = feeCapBelowBaseFee(tx, blockContext);
        if (feeCapTooLow != null) {
            throw callFailed(gasLimit, feeCapTooLow);
        }
        // geth's buyGas, fee or no fee: a call moving more than the sender holds
        // is refused as the chain would refuse it.
        EvmExecutionError.Infeasible shortfall = buyGasShortfall(tx, gasLimit, () -> balanceOf(tx.from(), blockContext));
        if (shortfall != null) {
            throw callFailed(gasLimit, shortfall);
        }
        long intrinsic = computeIntrinsicGas(tx.data());
        if (gasLimit < intrinsic) {
            throw callFailed(gasLimit, new EvmExecutionError.IntrinsicGasTooLow(gasLimit, intrinsic));
        }
        if (EvmFactory.calldataFloorActive(blockContext)) {
            long floor = computeCalldataFloor(tx.data());
            if (gasLimit < floor) {
                throw callFailed(gasLimit, new EvmExecutionError.FloorDataGasTooLow(gasLimit, floor));
            }
        }
        return new CallPlan(tx.from(), tx.to(), tx.data(), tx.value(), gasLimit, gasLimit - intrinsic,
                Wei.of(tx.effectiveGasPrice(blockContext.baseFeePerGas())), tx.gasLimit());
    }

    /** A check the call failed before running, as geth's {@code eth_call}
     *  reports it: with the gas limit it supplied. */
    private static EvmExecutionException callFailed(long suppliedGas, EvmExecutionError.Infeasible error) {
        return new EvmExecutionException(new EvmExecutionError.CallFailed(suppliedGas, error));
    }

    /** A non-zero fee cap (a legacy gas price is its own cap) below the block's
     *  base fee names a transaction no block at that base fee includes: geth's
     *  answer for a call and an estimate alike, returned here (null when the cap
     *  covers it). No fee is the exempt, fee-less simulation. */
    private static EvmExecutionError.FeeCapTooLow feeCapBelowBaseFee(UnsignedTransaction tx,
                                                                   BlockContext blockContext) {
        java.math.BigInteger feeCap = tx.feeCapOrZero();
        java.math.BigInteger baseFee = blockContext.baseFeePerGas() == null
                ? java.math.BigInteger.ZERO : blockContext.baseFeePerGas();
        return feeCap.signum() > 0 && feeCap.compareTo(baseFee) < 0
                ? new EvmExecutionError.FeeCapTooLow(tx.from(), feeCap, baseFee.longValue())
                : null;
    }

    /** The verified balance of {@code address} at {@code blockContext}'s state root. */
    private java.math.BigInteger balanceOf(Address address, BlockContext blockContext) {
        SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, new AccessTracker());
        var account = new SnapWorldUpdater(view).updater().get(
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(address.toByteArray())));
        return account == null ? java.math.BigInteger.ZERO : account.getBalance().toBigInteger();
    }

    /** EIP-7702 delegation designator prefix: an EOA whose code is
     *  {@code 0xef0100 || address} executes the delegate's code in its own context. */
    private static final Bytes DELEGATION_PREFIX = Bytes.fromHexString("0xef0100");

    /**
     * The code to execute for a call target, resolving an EIP-7702 delegation
     * designator one hop (the spec forbids chains — a delegate that itself holds
     * a designator is NOT followed; executing those raw bytes then correctly
     * yields an invalid-opcode halt). Without this, a plain call/estimate against
     * a delegated EOA (increasingly common post-Pectra) executed the raw
     * {@code 0xEF...} designator and died with INVALID_OPERATION.
     */
    private static Code resolveCode(EVM evm,
            org.hyperledger.besu.evm.worldstate.WorldUpdater scope,
            org.hyperledger.besu.evm.account.Account targetAccount) {
        Bytes contractCode = targetAccount == null ? Bytes.EMPTY : targetAccount.getCode();
        Hash contractCodeHash = targetAccount == null ? Hash.EMPTY : targetAccount.getCodeHash();
        var delegate = delegateOf(targetAccount);
        if (delegate.isPresent()) {
            var delegateAccount = scope.get(delegate.get());
            contractCode = delegateAccount == null ? Bytes.EMPTY : delegateAccount.getCode();
            contractCodeHash = delegateAccount == null ? Hash.EMPTY : delegateAccount.getCodeHash();
        }
        return evm.getOrCreateCachedJumpDest(contractCodeHash, contractCode);
    }

    /** The delegate an EIP-7702 designator in {@code account}'s code names, if any. */
    private static java.util.Optional<org.hyperledger.besu.datatypes.Address> delegateOf(
            org.hyperledger.besu.evm.account.Account account) {
        Bytes code = account == null ? Bytes.EMPTY : account.getCode();
        return code.size() == 23 && code.slice(0, 3).equals(DELEGATION_PREFIX)
                ? java.util.Optional.of(org.hyperledger.besu.datatypes.Address.wrap(code.slice(3, 20)))
                : java.util.Optional.empty();
    }

    /**
     * Yellow-Paper-Appendix-G intrinsic gas cost for a transaction:
     * 21000 base, 4 per zero byte of calldata, 16 per non-zero byte
     * (post-Istanbul, EIP-2028). EIP-2930 access lists and EIP-3860
     * init-code costs are not modelled in v1 — see {@code phase5-design.md}.
     */
    static long computeIntrinsicGas(byte[] calldata) {
        long gas = 21_000L;
        for (byte b : calldata) {
            gas += (b == 0) ? 4L : 16L;
        }
        return gas;
    }

    /**
     * EIP-7623's calldata floor: {@code 21000 + 10 × tokens}, where a zero byte
     * is one token and a non-zero byte four. Active from Prague
     * ({@link EvmFactory#calldataFloorActive}).
     */
    static long computeCalldataFloor(byte[] calldata) {
        long tokens = 0;
        for (byte b : calldata) {
            tokens += (b == 0) ? 1L : 4L;
        }
        return 21_000L + 10L * tokens;
    }

    private byte[] runOnce(Address sender, Address target, byte[] calldata,
                           java.math.BigInteger value, BlockContext blockContext) {
        AccessTracker tracker = new AccessTracker();
        SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, tracker);
        return runOnTracedView(sender, target, calldata, value, blockContext, view, OperationTracer.NO_TRACING);
    }

    /**
     * Drive a single EVM run against a caller-supplied {@link SyncStateView} and
     * {@link OperationTracer}. Used by {@code PrefetchingEvmExecutor} to share a
     * cache + tracer across the convergence loop's iterations; the public
     * {@link #callView} path still constructs a fresh per-call view.
     *
     * <p>Package-private: it's the seam the prefetch layer plugs into, but it's
     * not part of the public {@link EvmExecutor} contract.
     */
    byte[] runOnTracedView(Address sender, Address target, byte[] calldata,
                           java.math.BigInteger value, BlockContext blockContext,
                           SyncStateView view, OperationTracer tracer) {
        // A null sender means a from-less call → the anonymous VIEW_CALLER (Geth's
        // default). When the caller DID supply a from (eth_call from a wallet), use
        // it: contracts that gate on msg.sender (ERC-20 transfer/approve, …) must see
        // the real caller, else they revert ("transfer from the zero address").
        return runPlannedOnTracedView(viewPlan(sender, target, calldata, value), blockContext, view, tracer);
    }

    /** {@link #runOnTracedView} for a decided {@link CallPlan}: the seam both the
     *  plain and the transaction-object calls (and their prefetch loop) run on. */
    byte[] runPlannedOnTracedView(CallPlan plan, BlockContext blockContext,
                                  SyncStateView view, OperationTracer tracer) {
        MessageFrame frame = runPlanned(plan, blockContext, view, tracer);
        if (frame.getState() == MessageFrame.State.COMPLETED_SUCCESS) {
            return frame.getOutputData().toArrayUnsafe();
        }
        throw failureOf(frame, outOfGas(plan));
    }

    /**
     * Run {@code plan} on {@code view} and return the outer frame, finished:
     * {@code COMPLETED_SUCCESS}, or failed with its revert payload or halt
     * reason — the caller reads the outcome (and the gas) off it. The shared
     * runner of calls and of the estimate's probes.
     */
    private MessageFrame runPlanned(CallPlan plan, BlockContext blockContext,
                                    SyncStateView view, OperationTracer tracer) {
        return runPlanned(EvmFactory.buildForBlock(blockContext), plan, blockContext, view, tracer);
    }

    /** {@link #runPlanned(CallPlan, BlockContext, SyncStateView, OperationTracer)}
     *  on an EVM already built for {@code blockContext} — the estimate builds one
     *  for all of its runs. */
    private MessageFrame runPlanned(EvmFactory.EvmAndPrecompiles bundle, CallPlan plan, BlockContext blockContext,
                                    SyncStateView view, OperationTracer tracer) {
        CryptoProviders.ensureRegistered();
        EVM evm = bundle.evm();

        SnapWorldUpdater root = new SnapWorldUpdater(view);
        // Besu's EVM runs against a child updater so commit/revert of the
        // outer call doesn't pollute the read-through cache.
        org.hyperledger.besu.evm.worldstate.WorldUpdater scope = root.updater();

        Wei callValue = Wei.of(plan.value());
        org.hyperledger.besu.datatypes.Address besuTarget =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(plan.target().toByteArray()));
        org.hyperledger.besu.datatypes.Address besuSender =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(plan.sender().toByteArray()));
        org.hyperledger.besu.datatypes.Address besuCoinbase =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(blockContext.coinbase().toByteArray()));

        // geth's buyGas: the sender pays gas × price before the call runs, so the
        // call sees it debited. planCall checked the sender can afford it and
        // the prefetch loop primes the sender's real balance before its first
        // pass, so the floor at zero is only a safety net.
        if (!plan.price().isZero()) {
            var payer = scope.getOrCreate(besuSender);
            Wei cost = plan.price().multiply(plan.gasLimit());
            payer.setBalance(payer.getBalance().greaterOrEqualThan(cost) ? payer.getBalance().subtract(cost) : Wei.ZERO);
        }

        var targetAccount = scope.get(besuTarget);
        Code code = resolveCode(evm, scope, targetAccount);

        MessageFrame frame = MessageFrame.builder()
                .type(MessageFrame.Type.MESSAGE_CALL)
                .worldUpdater(scope)
                .initialGas(plan.frameGas())
                .address(besuTarget)
                .originator(besuSender)
                .contract(besuTarget)
                .gasPrice(plan.price())
                .blobGasPrice(Wei.ZERO)
                .inputData(Bytes.wrap(plan.data()))
                .sender(besuSender)
                .value(callValue)
                .apparentValue(callValue)
                .code(code)
                .blockValues(new BlockContextValues(blockContext))
                .completer(f -> {})
                .miningBeneficiary(besuCoinbase)
                // BLOCKHASH is not supported in Phase 0. Returning Hash.ZERO
                // would silently diverge from mainnet for any contract that
                // touches BLOCKHASH (or derived libraries — Compound v2 used
                // it as a "weak randomness" source). Fail fast instead; the
                // EVM will surface this as PRECOMPILE_ERROR / opaque halt and
                // we relabel it via the halt-reason mapping below.
                .blockHashLookup((bhFrame, n) -> {
                    throw new UnsupportedOperationException(
                            "BLOCKHASH not implemented; needs a verified block-hash provider");
                })
                // eth_call is a NON-static message call (matching Geth/Besu and our own
                // estimateGas path): the simulated tx may SSTORE — every ERC-20
                // transfer/approve does — and under isStatic(true) those state writes
                // halt with ILLEGAL_STATE_CHANGE, so even with the correct sender a
                // transfer simulation would fail. Writes are journalled into the
                // per-call child updater and discarded when the future completes;
                // nothing is committed, so view reads are unaffected.
                .isStatic(false)
                .build();
        // A delegated target's delegate starts the run warm, as the execution
        // specs, geth and revm start it: when the delegate's code calls back into
        // the target (RelayAdapt7702's multicall does), loading the delegate
        // again costs the warm price, not a cold access.
        delegateOf(targetAccount).ifPresent(frame::warmUpAddress);

        MessageCallProcessor processor = new MessageCallProcessor(evm, bundle.precompiles());

        // Drive the entire frame stack to completion. When a call performs
        // CALL/STATICCALL/DELEGATECALL, Besu pushes a child frame onto
        // frame.getMessageFrameStack() and suspends the parent at
        // CODE_SUSPENDED. The processor only acts on the frame at the top of
        // the stack, so we always re-fetch the top.
        Deque<MessageFrame> stack = frame.getMessageFrameStack();
        while (!stack.isEmpty()) {
            processor.process(stack.peek(), tracer);
        }

        return frame;
    }

    /**
     * The failure a finished, unsuccessful outer frame stands for.
     * {@code process()} auto-transitions REVERT/EXCEPTIONAL_HALT to a
     * COMPLETED_* terminal state before returning, so MessageFrame.State.REVERT
     * is unobservable; the outcome comes from the surviving signals
     * (revertReason / exceptionalHaltReason) on the original outer frame, not on
     * whatever popped last. Running out of gas is {@code outOfGas} — which
     * limit ran out is the caller's to say.
     */
    private static EvmExecutionException failureOf(MessageFrame frame, EvmExecutionError outOfGas) {
        if (frame.getRevertReason().isPresent()) {
            return new EvmExecutionException(
                    new EvmExecutionError.Reverted(frame.getRevertReason().get().toArrayUnsafe()));
        }
        var halt = frame.getExceptionalHaltReason();
        if (halt.isPresent() && halt.get() == ExceptionalHaltReason.INSUFFICIENT_GAS) {
            return new EvmExecutionException(outOfGas);
        }
        String detail = "halt=" + halt.map(ExceptionalHaltReason::name).orElse("UNKNOWN")
                + " state=" + frame.getState();
        // Halted, NOT Reverted: there is no chain-produced payload here, and hosts
        // serve Reverted's bytes verbatim as JSON-RPC revert data.
        return new EvmExecutionException(new EvmExecutionError.Halted(detail));
    }

    /** Running dry, as the plan's limit makes it: under a limit the caller set,
     *  geth's "out of gas" — an answer; under a larger one, capped to the budget,
     *  a refusal rather than an answer for a smaller limit; without one, the
     *  ordinary out-of-gas at this executor's own budget. The Rust call_tx twin. */
    private static EvmExecutionError outOfGas(CallPlan plan) {
        if (plan.callerGas() == null) {
            return new EvmExecutionError.OutOfGas();
        }
        return plan.callerGas() <= DEFAULT_GAS_LIMIT
                ? new EvmExecutionError.CallOutOfGas()
                : new EvmExecutionError.CallBudgetExceeded(DEFAULT_GAS_LIMIT, plan.callerGas());
    }

    /** Accessors used by {@code PrefetchingEvmExecutor} to share configuration. */
    SnapStateOracle oracle() { return oracle; }
    BytecodeCache bytecodeCache() { return bytecodeCache; }
    Executor executor() { return executor; }
}
