package io.myotis.evm;

import com.jaeckel.ethp2p.core.concurrent.Futures;

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
     * Sender- and value-aware view call: run {@code target.calldata} as if sent
     * by {@code sender} carrying {@code value} wei, against the state at
     * {@code blockContext.stateRoot()}, returning the raw return bytes. As with
     * {@link #callView(Address, byte[], BlockContext)}, state writes are journalled
     * and discarded — nothing is committed.
     *
     * <p>This is the entry point {@code eth_call} uses. MetaMask's confirm-screen
     * simulation sends a {@code from} (and sometimes a {@code value}), and any
     * contract whose logic depends on {@code msg.sender} — every ERC-20
     * {@code transfer}/{@code approve}, most dapp calls — must see the real caller.
     * Running such a call as the zero address makes it revert (e.g. USDC's
     * "ERC20: transfer from the zero address"), which is exactly the bug a
     * {@code from}-dropping eth_call produced.
     *
     * <p>A null {@code sender} means an anonymous zero-address caller (Geth's
     * default for a {@code from}-less call); a null {@code value} means zero.
     *
     * <p>The default implementation ignores {@code sender}/{@code value} and
     * behaves like {@link #callView(Address, byte[], BlockContext)}; the
     * production executors override it to thread both into the EVM frame.
     */
    default CompletableFuture<byte[]> callView(Address sender, Address target, byte[] calldata,
                                               java.math.BigInteger value, BlockContext blockContext) {
        return callView(target, calldata, blockContext);
    }

    /**
     * Estimate the gas required to execute {@code tx} against the state at
     * {@code blockContext.stateRoot()}.
     *
     * <p>Phase 5 deliverable. Earlier phases throw
     * {@link UnsupportedOperationException} via the default implementation.
     */
    default CompletableFuture<Long> estimateGas(UnsignedTransaction tx, BlockContext blockContext) {
        return Futures.failedFuture(
                new UnsupportedOperationException("estimateGas is a Phase 5 deliverable"));
    }
}
