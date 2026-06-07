package io.myotis.evm;

import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.ccipread.CcipReadHandler;
import io.myotis.evm.ccipread.OffchainLookupRevert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * {@link EvmExecutor} decorator that handles ERC-3668 CCIP-Read transparently.
 *
 * <p>When a wrapped {@code callView} reverts with the {@code OffchainLookup}
 * selector, this executor:
 * <ol>
 *   <li>Parses the revert payload into an {@link OffchainLookupRevert}.
 *   <li>Asks the {@link CcipReadHandler} to fetch from the listed gateways
 *       (URL template substitution + GET/POST routing per spec).
 *   <li>Re-enters the EVM with
 *       {@code callbackFunction(response, extraData)} targeted at the
 *       original {@code sender}, recursing through this decorator so a
 *       chained CCIP-Read on the callback is also handled — up to
 *       {@link CcipReadHandler#MAX_RECURSION_DEPTH} (1, plan-mandated).
 * </ol>
 *
 * <p>Composes with any other {@link EvmExecutor}: in production the wallet
 * builds {@code new CcipReadEvmExecutor(new PrefetchingEvmExecutor(...))}
 * so prefetching and CCIP-Read both work, with CCIP-Read on the outside
 * because the OffchainLookup revert can only be observed at the call
 * boundary.
 *
 * <p>If a non-CCIP-Read revert escapes the wrapped executor, this class
 * passes it through unchanged.
 *
 * <p><strong>Async-by-contract.</strong> The handler chain is composed via
 * {@link CompletableFuture#thenCompose} all the way down — no
 * {@code join()}, no blocking on the EVM executor's thread pool. The
 * gateway transport is free to use whatever async HTTP client it likes.
 */
public final class CcipReadEvmExecutor implements EvmExecutor {

    private static final Logger log = LoggerFactory.getLogger(CcipReadEvmExecutor.class);

    private final EvmExecutor delegate;
    private final CcipReadHandler handler;

    /**
     * Set once this executor observes (and starts handling) an OffchainLookup
     * revert. A wallet that builds one executor per resolution can read this
     * afterwards to learn whether the answer came from an ERC-3668 gateway.
     * That matters for fallback policy: an offchain answer is determined by the
     * gateway, not by which execution-layer state root we ran against, so there
     * is no point re-resolving the same name against a different (e.g. head)
     * root when an offchain lookup already produced the (non-)answer.
     */
    private final java.util.concurrent.atomic.AtomicBoolean usedOffchain =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    public CcipReadEvmExecutor(EvmExecutor delegate, CcipReadHandler handler) {
        this.delegate = delegate;
        this.handler = handler;
    }

    /** Whether this executor handled at least one ERC-3668 OffchainLookup. */
    public boolean usedOffchain() {
        return usedOffchain.get();
    }

    @Override
    public CompletableFuture<byte[]> callView(Address target, byte[] calldata, BlockContext blockContext) {
        return tryWithCcipRead(target, calldata, blockContext, 0);
    }

    private CompletableFuture<byte[]> tryWithCcipRead(
            Address target, byte[] calldata, BlockContext ctx, int depth) {
        return delegate.callView(target, calldata, ctx)
                .exceptionallyCompose(t -> handleException(t, ctx, depth));
    }

    private CompletableFuture<byte[]> handleException(Throwable t, BlockContext ctx, int depth) {
        Throwable cause = unwrap(t);
        Optional<OffchainLookupRevert> lookup = extractLookup(cause);
        if (lookup.isEmpty()) {
            // Not a CCIP-Read revert; rethrow whatever the delegate produced.
            return CompletableFuture.failedFuture(cause);
        }

        if (depth >= CcipReadHandler.MAX_RECURSION_DEPTH) {
            log.warn("[ccip] recursion depth {} exceeds cap {}; failing",
                    depth, CcipReadHandler.MAX_RECURSION_DEPTH);
            return CompletableFuture.failedFuture(new EvmExecutionException(
                    new EvmExecutionError.CcipGatewayFailed(
                            List.copyOf(lookup.get().urls()),
                            List.of("CCIP-Read recursion depth " + depth
                                    + " exceeds cap " + CcipReadHandler.MAX_RECURSION_DEPTH))));
        }

        usedOffchain.set(true);
        log.debug("[ccip] caught OffchainLookup; fetching from {} gateway(s)",
                lookup.get().urls().size());
        return handler.handle(lookup.get())
                .thenCompose(gatewayResponse -> {
                    byte[] callbackCalldata = encodeCallback(lookup.get(), gatewayResponse);
                    log.debug("[ccip] re-entering EVM (sender={}, depth={})",
                            lookup.get().sender(), depth + 1);
                    return tryWithCcipRead(lookup.get().sender(), callbackCalldata, ctx, depth + 1);
                });
    }

    /**
     * Build the calldata for the resolver's callback: a 4-byte selector
     * followed by ABI-encoded {@code (bytes response, bytes extraData)}
     * per ERC-3668 §6.
     */
    private static byte[] encodeCallback(OffchainLookupRevert lookup, byte[] response) {
        byte[] selector = lookup.callbackSelector();
        byte[] body = AbiEncoder.encodeRaw(
                AbiEncoder.bytes(response),
                AbiEncoder.bytes(lookup.extraData()));
        byte[] out = new byte[selector.length + body.length];
        System.arraycopy(selector, 0, out, 0, selector.length);
        System.arraycopy(body, 0, out, selector.length, body.length);
        return out;
    }

    private static Optional<OffchainLookupRevert> extractLookup(Throwable t) {
        if (!(t instanceof EvmExecutionException eee)) return Optional.empty();
        if (!(eee.error() instanceof EvmExecutionError.Reverted r)) return Optional.empty();
        return OffchainLookupRevert.tryParse(r.data());
    }

    private static Throwable unwrap(Throwable t) {
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }
}
