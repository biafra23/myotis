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
        return CompletableFuture.supplyAsync(() -> runOnce(target, calldata, blockContext), executor);
    }

    private byte[] runOnce(Address target, byte[] calldata, BlockContext blockContext) {
        CryptoProviders.ensureRegistered();
        EvmFactory.EvmAndPrecompiles bundle = EvmFactory.buildForBlock(blockContext);
        EVM evm = bundle.evm();

        AccessTracker tracker = new AccessTracker();
        SyncStateView view = new SyncStateView(oracle, blockContext.stateRoot(), bytecodeCache, tracker);
        SnapWorldUpdater root = new SnapWorldUpdater(view);
        // Besu's EVM runs against a child updater so commit/revert of the
        // outer call doesn't pollute the read-through cache.
        org.hyperledger.besu.evm.worldstate.WorldUpdater scope = root.updater();

        org.hyperledger.besu.datatypes.Address besuTarget =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(target.toByteArray()));
        org.hyperledger.besu.datatypes.Address besuSender =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(VIEW_CALLER.toByteArray()));
        org.hyperledger.besu.datatypes.Address besuCoinbase =
                org.hyperledger.besu.datatypes.Address.wrap(Bytes.wrap(blockContext.coinbase().toByteArray()));

        Bytes contractCode = scope.get(besuTarget) == null
                ? Bytes.EMPTY
                : scope.get(besuTarget).getCode();
        Hash contractCodeHash = scope.get(besuTarget) == null
                ? Hash.EMPTY
                : scope.get(besuTarget).getCodeHash();
        Code code = evm.getCode(contractCodeHash, contractCode);

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
                .value(Wei.ZERO)
                .apparentValue(Wei.ZERO)
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
                .blockHashLookup(n -> {
                    throw new UnsupportedOperationException(
                            "BLOCKHASH not implemented; needs a verified block-hash provider");
                })
                .isStatic(true)
                .build();

        MessageCallProcessor processor = new MessageCallProcessor(evm, bundle.precompiles());

        // Drive the entire frame stack to completion. When a call performs
        // CALL/STATICCALL/DELEGATECALL, Besu pushes a child frame onto
        // frame.getMessageFrameStack() and suspends the parent at
        // CODE_SUSPENDED. The processor only acts on the frame at the top of
        // the stack, so we always re-fetch the top.
        Deque<MessageFrame> stack = frame.getMessageFrameStack();
        while (!stack.isEmpty()) {
            processor.process(stack.peek(), OperationTracer.NO_TRACING);
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
}
