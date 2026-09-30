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
        // The ceiling (geth's `hi`, #509): the executor's budget — never above
        // what a transaction may carry at all (EIP-7825 from Osaka) — lowered by
        // the caller's gas limit (below 21000 geth reads it as no limit, and so
        // do we) and, under a fee cap, by what the sender can pay for. The answer
        // never exceeds it, and a transaction that does not succeed within it
        // is geth's "gas required exceeds allowance".
        long ceiling = Math.min(DEFAULT_GAS_LIMIT, EvmFactory.txGasLimitCap(blockContext));
        if (tx.gasLimit() != null && tx.gasLimit() >= 21_000L) {
            ceiling = Math.min(ceiling, tx.gasLimit());
        }
        java.math.BigInteger feeCap = tx.feeCapOrZero();
        if (feeCap.signum() > 0) {
            java.math.BigInteger balance = balanceOf(tx.from(), blockContext);
            if (tx.value().compareTo(balance) >= 0) {
                throw new EvmExecutionException(new EvmExecutionError.InsufficientFundsForTransfer());
            }
            java.math.BigInteger fundable = balance.subtract(tx.value()).divide(feeCap);
            if (fundable.compareTo(java.math.BigInteger.valueOf(ceiling)) < 0) {
                ceiling = fundable.longValue();
            }
        }
        // geth checks the fee cap against the base fee when it first RUNS the
        // transaction: after the affordability checks above, before the intrinsic
        // cost is weighed against the ceiling (the Rust estimate's order) — and
        // its estimator reports that run's refusal with the ceiling it ran at.
        EvmExecutionError.FeeCapTooLow feeCapTooLow = feeCapBelowBaseFee(tx, blockContext);
        if (feeCapTooLow != null) {
            throw new EvmExecutionException(new EvmExecutionError.FailedWithGas(ceiling, feeCapTooLow));
        }
        // EIP-7623: from Prague on a transaction is charged at least this floor,
        // so the answer must cover it (the Rust estimate's `tx_gas_used` twin).
        long floor = EvmFactory.calldataFloorActive(blockContext) ? computeCalldataFloor(tx.data()) : 0L;
        if (intrinsicGas > ceiling || floor > ceiling) {
            // The limit does not even cover the intrinsic cost (or the floor).
            // Note: a budget of exactly 0 is legal — a plain ETH transfer to an
            // existing EOA at gasLimit=21000 has no EVM execution and
            // runForEstimation correctly returns evmUsed=0.
            throw new EvmExecutionException(new EvmExecutionError.GasAllowanceExceeded(ceiling));
        }
        long evmUsed = runForEstimation(tx, blockContext, ceiling - intrinsicGas, ceiling);
        long total = Math.max(intrinsicGas + evmUsed, floor);
        // 15% safety buffer per the plan. A slightly-too-high estimate just
        // costs the user some priority fee; a slightly-too-low one OOG's
        // the broadcast transaction — so round *up* strictly. Math.round
        // can round down (e.g. for totals where total * 1.15 lands just
        // below x.5), defeating the safety property. Never above the ceiling:
        // the run just succeeded within it, so the ceiling is itself a limit
        // that works — geth's invariant.
        return Math.min((long) Math.ceil(total * 1.15), ceiling);
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
     * is debited at, and whether the limit is the caller's own (running out of it
     * is then the caller's answer, geth's "out of gas").
     */
    record CallPlan(io.myotis.evm.Address sender, io.myotis.evm.Address target, byte[] data,
                    java.math.BigInteger value, long gasLimit, long frameGas, Wei price,
                    boolean callerLimited) {}

    /** The plan a plain view call has always run with: the whole budget handed to
     *  the frame, no price, no debit. */
    static CallPlan viewPlan(io.myotis.evm.Address sender, io.myotis.evm.Address target, byte[] calldata,
                             java.math.BigInteger value) {
        return new CallPlan(sender != null ? sender : VIEW_CALLER, target, calldata,
                value != null ? value : java.math.BigInteger.ZERO,
                DEFAULT_GAS_LIMIT, DEFAULT_GAS_LIMIT, Wei.ZERO, false);
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
        // geth's buyGas, fee or no fee: the sender must hold gas × fee cap +
        // value — a call moving more than the sender holds is refused as the
        // chain would refuse it — and that sum must fit 256 bits.
        java.math.BigInteger want = java.math.BigInteger.valueOf(gasLimit).multiply(tx.feeCapOrZero()).add(tx.value());
        if (want.bitLength() > 256) {
            throw callFailed(gasLimit, new EvmExecutionError.RequiredBalanceOverflow(tx.from()));
        }
        if (want.signum() > 0) {
            java.math.BigInteger have = balanceOf(tx.from(), blockContext);
            if (have.compareTo(want) < 0) {
                throw callFailed(gasLimit, new EvmExecutionError.InsufficientFunds(tx.from(), have, want));
            }
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
                Wei.of(tx.effectiveGasPrice(blockContext.baseFeePerGas())),
                tx.gasLimit() != null && tx.gasLimit() <= DEFAULT_GAS_LIMIT);
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

    /**
     * Run the EVM with transaction-shaped frame parameters and return the
     * EVM-side gas consumed. Throws {@link EvmExecutionException} on
     * revert / exceptional halt — the plan mandates that estimation does
     * NOT return a number for a reverting transaction (the caller must
     * not broadcast it).
     */
    private long runForEstimation(UnsignedTransaction tx, BlockContext blockContext, long evmBudget,
                                  long ceiling) {
        EvmFactory.EvmAndPrecompiles bundle = EvmFactory.buildForBlock(blockContext);
        EVM evm = bundle.evm();

        AccessTracker tracker = new AccessTracker();
        SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, tracker);
        SnapWorldUpdater root = new SnapWorldUpdater(view);
        org.hyperledger.besu.evm.worldstate.WorldUpdater scope = root.updater();

        org.hyperledger.besu.datatypes.Address besuTarget =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(tx.to().toByteArray()));
        org.hyperledger.besu.datatypes.Address besuSender =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(tx.from().toByteArray()));
        org.hyperledger.besu.datatypes.Address besuCoinbase =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(blockContext.coinbase().toByteArray()));

        var targetAccount = scope.get(besuTarget);
        Code code = resolveCode(evm, scope, targetAccount);

        Wei value = Wei.of(tx.value());

        MessageFrame frame = MessageFrame.builder()
                .type(MessageFrame.Type.MESSAGE_CALL)
                .worldUpdater(scope)
                .initialGas(evmBudget)
                .address(besuTarget)
                .originator(besuSender)
                .contract(besuTarget)
                // What GASPRICE reads: the request's effective price (zero
                // when it names no fee field) — a relayer that pays itself
                // gasleft() × tx.gasprice costs more when it is not zero.
                .gasPrice(Wei.of(tx.effectiveGasPrice(blockContext.baseFeePerGas())))
                .blobGasPrice(Wei.ZERO)
                .inputData(Bytes.wrap(tx.data()))
                .sender(besuSender)
                .value(value)
                .apparentValue(value)
                .code(code)
                .blockValues(new BlockContextValues(blockContext))
                .completer(f -> {})
                .miningBeneficiary(besuCoinbase)
                .blockHashLookup((bhFrame, n) -> {
                    throw new UnsupportedOperationException(
                            "BLOCKHASH not implemented; needs a verified block-hash provider");
                })
                // Estimation runs as a real (non-static) call so SSTOREs
                // inside the target's bytecode can be metered correctly,
                // including refund accounting. The per-call journal is
                // discarded after we read getRemainingGas; nothing
                // mutates the chain.
                .isStatic(false)
                .build();

        MessageCallProcessor processor = new MessageCallProcessor(evm, bundle.precompiles());
        Deque<MessageFrame> stack = frame.getMessageFrameStack();
        while (!stack.isEmpty()) {
            processor.process(stack.peek(), OperationTracer.NO_TRACING);
        }

        if (frame.getState() == MessageFrame.State.COMPLETED_SUCCESS) {
            return evmBudget - frame.getRemainingGas();
        }
        if (frame.getRevertReason().isPresent()) {
            throw new EvmExecutionException(
                    new EvmExecutionError.Reverted(frame.getRevertReason().get().toArrayUnsafe()));
        }
        var halt = frame.getExceptionalHaltReason();
        if (halt.isPresent() && halt.get() == ExceptionalHaltReason.INSUFFICIENT_GAS) {
            // Out of gas AT the ceiling: more than the caller allowed.
            throw new EvmExecutionException(new EvmExecutionError.GasAllowanceExceeded(ceiling));
        }
        String detail = "halt=" + halt.map(ExceptionalHaltReason::name).orElse("UNKNOWN")
                + " state=" + frame.getState();
        // Halted, NOT Reverted: there is no chain-produced payload here, and hosts
        // serve Reverted's bytes verbatim as JSON-RPC revert data.
        throw new EvmExecutionException(new EvmExecutionError.Halted(detail));
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
        if (contractCode.size() == 23 && contractCode.slice(0, 3).equals(DELEGATION_PREFIX)) {
            org.hyperledger.besu.datatypes.Address delegate =
                    org.hyperledger.besu.datatypes.Address.wrap(contractCode.slice(3, 20));
            var delegateAccount = scope.get(delegate);
            contractCode = delegateAccount == null ? Bytes.EMPTY : delegateAccount.getCode();
            contractCodeHash = delegateAccount == null ? Hash.EMPTY : delegateAccount.getCodeHash();
        }
        return evm.getOrCreateCachedJumpDest(contractCodeHash, contractCode);
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
        CryptoProviders.ensureRegistered();
        EvmFactory.EvmAndPrecompiles bundle = EvmFactory.buildForBlock(blockContext);
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

        // process() auto-transitions REVERT/EXCEPTIONAL_HALT to a COMPLETED_*
        // terminal state before returning, so MessageFrame.State.REVERT is
        // unobservable here. Derive the outcome from the surviving signals
        // (revertReason / exceptionalHaltReason / output) on the original
        // outer frame, not on whatever popped last.
        if (frame.getState() == MessageFrame.State.COMPLETED_SUCCESS) {
            return frame.getOutputData().toArrayUnsafe();
        }
        if (frame.getRevertReason().isPresent()) {
            throw new EvmExecutionException(
                    new EvmExecutionError.Reverted(frame.getRevertReason().get().toArrayUnsafe()));
        }
        // Halt without an explicit revert payload: map the halt reason to
        // OutOfGas where applicable, otherwise surface a Halted with a
        // human-readable detail so the failure isn't opaque.
        var halt = frame.getExceptionalHaltReason();
        if (halt.isPresent() && halt.get() == ExceptionalHaltReason.INSUFFICIENT_GAS) {
            // Out of a limit the CALLER set: geth's "out of gas", an answer. At
            // this executor's own budget it stays the ordinary out-of-gas.
            throw new EvmExecutionException(plan.callerLimited()
                    ? new EvmExecutionError.CallOutOfGas() : new EvmExecutionError.OutOfGas());
        }
        String detail = "halt=" + halt.map(ExceptionalHaltReason::name).orElse("UNKNOWN")
                + " state=" + frame.getState();
        // Halted, NOT Reverted: there is no chain-produced payload here, and hosts
        // serve Reverted's bytes verbatim as JSON-RPC revert data.
        throw new EvmExecutionException(new EvmExecutionError.Halted(detail));
    }

    /** Accessors used by {@code PrefetchingEvmExecutor} to share configuration. */
    SnapStateOracle oracle() { return oracle; }
    BytecodeCache bytecodeCache() { return bytecodeCache; }
    Executor executor() { return executor; }
}
