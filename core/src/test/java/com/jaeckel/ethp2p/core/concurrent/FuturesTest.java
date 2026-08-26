package com.jaeckel.ethp2p.core.concurrent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Pins Futures to the CompletableFuture contracts it replaces for minSdk 29. */
@Timeout(10)
class FuturesTest {

    @Test
    void failedFutureCarriesTheExactCause() {
        IllegalStateException cause = new IllegalStateException("boom");
        CompletableFuture<String> f = Futures.failedFuture(cause);
        assertTrue(f.isCompletedExceptionally());
        ExecutionException ex = assertThrows(ExecutionException.class, f::get);
        assertSame(cause, ex.getCause());
    }

    @Test
    void orTimeoutReturnsTheSameFutureAndFiresWithTimeoutException() {
        CompletableFuture<String> f = new CompletableFuture<>();
        assertSame(f, Futures.orTimeout(f, 50, TimeUnit.MILLISECONDS));
        ExecutionException ex = assertThrows(ExecutionException.class, () -> f.get(5, TimeUnit.SECONDS));
        assertInstanceOf(TimeoutException.class, ex.getCause());
    }

    @Test
    void orTimeoutDoesNotFireOnceCompleted() throws Exception {
        CompletableFuture<String> f = new CompletableFuture<>();
        Futures.orTimeout(f, 100, TimeUnit.MILLISECONDS);
        f.complete("done");
        Thread.sleep(250);
        assertEquals("done", f.get());
        assertFalse(f.isCompletedExceptionally());
    }

    @Test
    void orTimeoutOnACompletedFutureIsANoOp() throws Exception {
        CompletableFuture<String> f = CompletableFuture.completedFuture("done");
        assertSame(f, Futures.orTimeout(f, 1, TimeUnit.NANOSECONDS));
        assertEquals("done", f.get());
    }

    @Test
    void exceptionallyComposePassesSuccessThroughWithoutInvokingFn() throws Exception {
        AtomicBoolean invoked = new AtomicBoolean();
        CompletableFuture<String> f = CompletableFuture.completedFuture("ok");
        CompletableFuture<String> out = Futures.exceptionallyCompose(f, t -> {
            invoked.set(true);
            return CompletableFuture.completedFuture("recovered");
        });
        assertEquals("ok", out.get());
        assertFalse(invoked.get());
    }

    @Test
    void exceptionallyComposeRecoversFromFailure() throws Exception {
        CompletableFuture<String> f = Futures.failedFuture(new IllegalStateException("boom"));
        CompletableFuture<String> out = Futures.exceptionallyCompose(f,
                t -> CompletableFuture.completedFuture("recovered:" + t.getMessage()));
        assertEquals("recovered:boom", out.get());
    }

    @Test
    void exceptionallyComposePropagatesAFailedRecovery() {
        IllegalArgumentException second = new IllegalArgumentException("second");
        CompletableFuture<String> f = Futures.failedFuture(new IllegalStateException("first"));
        CompletableFuture<String> out = Futures.exceptionallyCompose(f, t -> Futures.failedFuture(second));
        ExecutionException ex = assertThrows(ExecutionException.class, out::get);
        assertSame(second, ex.getCause());
    }

    @Test
    void exceptionallyComposePropagatesAThrowingFn() {
        // Same as the CompletionStage default implementation: a throw from fn
        // fails the resulting stage (wrapped by the completion machinery).
        CompletableFuture<String> f = Futures.failedFuture(new IllegalStateException("first"));
        CompletableFuture<String> out = Futures.exceptionallyCompose(f, t -> {
            throw new CompletionException(new IllegalArgumentException("thrown"));
        });
        ExecutionException ex = assertThrows(ExecutionException.class, out::get);
        assertInstanceOf(IllegalArgumentException.class, ex.getCause());
    }
}
