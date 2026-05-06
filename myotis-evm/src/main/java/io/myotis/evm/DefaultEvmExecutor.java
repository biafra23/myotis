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
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.processor.MessageCallProcessor;
import org.hyperledger.besu.evm.tracing.OperationTracer;

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
                .blockHashLookup(n -> Hash.ZERO)
                .isStatic(true)
                .build();

        // Drive the frame to a terminal state. AbstractMessageProcessor.process()
        // walks the state machine: NOT_STARTED → CODE_EXECUTING (via start()) →
        // runToHalt → CODE_SUCCESS/REVERT/EXCEPTIONAL_HALT → COMPLETED_*.
        // Calling start() directly only initialises and is not enough.
        // Child frames (CALL/CREATE) are kept on the EVM's own stack; we
        // re-process the parent until it reaches a COMPLETED_* state.
        MessageCallProcessor processor = new MessageCallProcessor(evm, bundle.precompiles());
        while (frame.getState() != MessageFrame.State.COMPLETED_SUCCESS
                && frame.getState() != MessageFrame.State.COMPLETED_FAILED) {
            processor.process(frame, OperationTracer.NO_TRACING);
        }

        MessageFrame.State state = frame.getState();
        if (state == MessageFrame.State.COMPLETED_SUCCESS) {
            return frame.getOutputData().toArrayUnsafe();
        }
        if (state == MessageFrame.State.REVERT) {
            byte[] data = frame.getRevertReason().map(Bytes::toArrayUnsafe).orElse(new byte[0]);
            throw new EvmExecutionException(new EvmExecutionError.Reverted(data));
        }
        // EXCEPTIONAL_HALT, COMPLETED_FAILED, etc. Surface the halt reason so
        // this isn't an opaque "execution failed" — investigations against
        // unfamiliar bytecode rely on it.
        String detail = state + frame.getExceptionalHaltReason()
                .map(r -> "/" + r.name()).orElse("");
        throw new EvmExecutionException(
                new EvmExecutionError.Reverted(detail.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }
}
