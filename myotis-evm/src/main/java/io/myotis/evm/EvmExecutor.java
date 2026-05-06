package io.myotis.evm;

import java.util.concurrent.CompletableFuture;

/**
 * Public surface of myotis-evm.
 *
 * <p>The plan's Kotlin signature returns {@code Result<ByteArray, EvmExecutionError>}.
 * In Java we surface the same shape via {@link CompletableFuture}: the future
 * completes with the return bytes on success or fails with an
 * {@link EvmExecutionException} whose {@link EvmExecutionException#error()}
 * carries the typed cause.
 *
 * <p>Execution is stateless from the caller's perspective. No persistent VM
 * instance is shared across calls; each invocation reads only the state needed
 * to answer the call and discards everything else when it completes.
 */
public interface EvmExecutor {

    /**
     * Execute a view-style call: invoke {@code target} with {@code calldata}
     * against the state at {@code blockContext.stateRoot()} and return the raw
     * return bytes.
     *
     * <p>State writes performed during execution are journalled in memory and
     * discarded once the call completes; this method never mutates the chain.
     *
     * <p>ERC-3668 CCIP-Read handling is a Phase 4 deliverable. Until that
     * lands, a target that reverts with {@code OffchainLookup} surfaces as
     * {@link EvmExecutionError.Reverted} and the caller cannot resolve it
     * without an explicit gateway round trip. The Phase 4 commit will catch
     * the revert in this implementation and re-enter the EVM with the
     * gateway response transparently.
     */
    CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext);

    /**
     * Estimate the gas required to execute {@code tx} against the state at
     * {@code blockContext.stateRoot()}.
     *
     * <p>Phase 5 deliverable. Earlier phases throw
     * {@link UnsupportedOperationException} via the default implementation.
     */
    default CompletableFuture<Long> estimateGas(UnsignedTransaction tx, BlockContext blockContext) {
        return CompletableFuture.failedFuture(
                new UnsupportedOperationException("estimateGas is a Phase 5 deliverable"));
    }
}
