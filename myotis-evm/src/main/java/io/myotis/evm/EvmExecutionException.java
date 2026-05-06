package io.myotis.evm;

/**
 * Runtime exception wrapping a typed {@link EvmExecutionError}.
 *
 * <p>The plan's Kotlin signature returns {@code Result<ByteArray, EvmExecutionError>}.
 * In Java we surface the same information by completing a {@code CompletableFuture}
 * exceptionally with this exception, whose {@link #error()} carries the typed cause.
 * Callers pattern-match on {@code error()} the way they would on the Kotlin sealed class.
 */
public final class EvmExecutionException extends RuntimeException {

    private final EvmExecutionError error;

    public EvmExecutionException(EvmExecutionError error) {
        super(error.toString());
        this.error = error;
    }

    public EvmExecutionException(EvmExecutionError error, Throwable cause) {
        super(error.toString(), cause);
        this.error = error;
    }

    public EvmExecutionError error() {
        return error;
    }
}
