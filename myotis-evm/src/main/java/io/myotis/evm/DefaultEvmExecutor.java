package io.myotis.evm;

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
            return CompletableFuture.failedFuture(new UnsupportedOperationException(
                    "Phase 5 does not yet handle contract creation (to=null)"));
        }
        return CompletableFuture.supplyAsync(() -> estimateGasOnce(tx, blockContext), executor);
    }

    private long estimateGasOnce(UnsignedTransaction tx, BlockContext blockContext) {
        CryptoProviders.ensureRegistered();
        long intrinsicGas = computeIntrinsicGas(tx.data());
        long ceiling = tx.gasLimit() != null ? tx.gasLimit() : DEFAULT_GAS_LIMIT;
        long evmBudget = ceiling - intrinsicGas;
        if (evmBudget < 0) {
            // The intrinsic cost alone exceeds the ceiling — caller's
            // gasLimit is too low even before the EVM gets a chance to run.
            // Note: a budget of exactly 0 is legal — a plain ETH transfer
            // to an existing EOA at gasLimit=21000 has no EVM execution
            // and runForEstimation correctly returns evmUsed=0.
            throw new EvmExecutionException(new EvmExecutionError.OutOfGas());
        }
        long evmUsed = runForEstimation(tx, blockContext, evmBudget);
        long total = intrinsicGas + evmUsed;
        // 15% safety buffer per the plan. A slightly-too-high estimate just
        // costs the user some priority fee; a slightly-too-low one OOG's
        // the broadcast transaction — so round *up* strictly. Math.round
        // can round down (e.g. for totals where total * 1.15 lands just
        // below x.5), defeating the safety property.
        return (long) Math.ceil(total * 1.15);
    }

    /**
     * Run the EVM with transaction-shaped frame parameters and return the
     * EVM-side gas consumed. Throws {@link EvmExecutionException} on
     * revert / exceptional halt — the plan mandates that estimation does
     * NOT return a number for a reverting transaction (the caller must
     * not broadcast it).
     */
    private long runForEstimation(UnsignedTransaction tx, BlockContext blockContext, long evmBudget) {
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
                .gasPrice(Wei.ZERO)
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
            throw new EvmExecutionException(new EvmExecutionError.OutOfGas());
        }
        String detail = "halt=" + halt.map(ExceptionalHaltReason::name).orElse("UNKNOWN")
                + " state=" + frame.getState();
        throw new EvmExecutionException(
                new EvmExecutionError.Reverted(detail.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
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
        CryptoProviders.ensureRegistered();
        EvmFactory.EvmAndPrecompiles bundle = EvmFactory.buildForBlock(blockContext);
        EVM evm = bundle.evm();

        SnapWorldUpdater root = new SnapWorldUpdater(view);
        // Besu's EVM runs against a child updater so commit/revert of the
        // outer call doesn't pollute the read-through cache.
        org.hyperledger.besu.evm.worldstate.WorldUpdater scope = root.updater();

        // A null sender means a from-less call → the anonymous VIEW_CALLER (Geth's
        // default). When the caller DID supply a from (eth_call from a wallet), use
        // it: contracts that gate on msg.sender (ERC-20 transfer/approve, …) must see
        // the real caller, else they revert ("transfer from the zero address").
        io.myotis.evm.Address effectiveSender = sender != null ? sender : VIEW_CALLER;
        Wei callValue = value != null ? Wei.of(value) : Wei.ZERO;
        org.hyperledger.besu.datatypes.Address besuTarget =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(target.toByteArray()));
        org.hyperledger.besu.datatypes.Address besuSender =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(effectiveSender.toByteArray()));
        org.hyperledger.besu.datatypes.Address besuCoinbase =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(blockContext.coinbase().toByteArray()));

        var targetAccount = scope.get(besuTarget);
        Code code = resolveCode(evm, scope, targetAccount);

        MessageFrame frame = MessageFrame.builder()
                .type(MessageFrame.Type.MESSAGE_CALL)
                .worldUpdater(scope)
                .initialGas(DEFAULT_GAS_LIMIT)
                .address(besuTarget)
                .originator(besuSender)
                .contract(besuTarget)
                .gasPrice(Wei.ZERO)
                .blobGasPrice(Wei.ZERO)
                .inputData(Bytes.wrap(calldata))
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
        // OutOfGas where applicable, otherwise surface a Reverted with a
        // human-readable detail so the failure isn't opaque.
        var halt = frame.getExceptionalHaltReason();
        if (halt.isPresent() && halt.get() == ExceptionalHaltReason.INSUFFICIENT_GAS) {
            throw new EvmExecutionException(new EvmExecutionError.OutOfGas());
        }
        String detail = "halt=" + halt.map(ExceptionalHaltReason::name).orElse("UNKNOWN")
                + " state=" + frame.getState();
        throw new EvmExecutionException(
                new EvmExecutionError.Reverted(detail.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    /** Accessors used by {@code PrefetchingEvmExecutor} to share configuration. */
    SnapStateOracle oracle() { return oracle; }
    BytecodeCache bytecodeCache() { return bytecodeCache; }
    Executor executor() { return executor; }
}
