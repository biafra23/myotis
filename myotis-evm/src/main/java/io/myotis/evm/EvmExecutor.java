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
     * <p>ERC-3668 CCIP-Read is handled by the {@code CcipReadEvmExecutor}
     * decorator, which catches a target's {@code OffchainLookup} revert, performs
     * the gateway round trip and re-enters the EVM with the gateway response
     * transparently. On a bare executor (no decorator) such a revert surfaces as
     * {@link EvmExecutionError.Reverted} and the caller cannot resolve it without
     * an explicit gateway round trip.
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
     * {@code eth_call} for a transaction object (#509): the sender-aware
     * {@link #callView(Address, Address, byte[], java.math.BigInteger, BlockContext)}
     * plus {@code tx}'s gas limit and fees, applied as geth's {@code eth_call}
     * applies them — the limit bounds the call, a fee is checked against the base
     * fee and the sender's balance and charged before the call runs. A call that
     * cannot succeed within them fails with geth's answer
     * ({@link EvmExecutionError.CallOutOfGas}, {@link EvmExecutionError.InsufficientFunds}, …).
     *
     * <p>The default serves only a transaction without them and fails anything
     * else rather than run a call the caller did not describe.
     */
    default CompletableFuture<byte[]> callTx(UnsignedTransaction tx, BlockContext blockContext) {
        if (tx.gasLimit() != null || tx.gasFeeCap() != null || tx.gasTipCap() != null) {
            return Futures.failedFuture(new UnsupportedOperationException(
                    "this executor does not apply a transaction's gas limit or fees"));
        }
        return callView(tx.from(), tx.to(), tx.data(), tx.value(), blockContext);
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
