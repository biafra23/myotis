package com.jaeckel.ethp2p.core.concurrent;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

/**
 * Android-safe stand-ins for the {@link CompletableFuture} conveniences the app
 * cannot call directly at minSdk 29: {@code failedFuture} and {@code orTimeout}
 * exist only from Android API 31, {@code exceptionallyCompose} only from API 34,
 * and NONE of them are covered by core-library desugaring or D8 backports (the
 * desugar_jdk_libs configuration contains no CompletableFuture entries at any
 * release through 2.1.5). Each helper reproduces the JDK method's contract
 * exactly, so JVM hosts behave identically.
 */
public final class Futures {

    private Futures() {}

    /** Equivalent of {@link CompletableFuture#failedFuture(Throwable)} (API 31+). */
    public static <T> CompletableFuture<T> failedFuture(Throwable cause) {
        CompletableFuture<T> future = new CompletableFuture<>();
        future.completeExceptionally(cause);
        return future;
    }

    /**
     * Equivalent of {@code future.orTimeout(timeout, unit)} (API 31+): completes
     * {@code future} exceptionally with a {@link TimeoutException} if it is not
     * done within the timeout, and returns the same future. Like the JDK, the
     * timer task is cancelled as soon as the future completes — and, also like
     * the JDK's internal delayer, dependents of a future completed BY the
     * timeout run on the single shared timer thread, so keep timeout
     * continuations light (hand heavy work to an executor).
     */
    public static <T> CompletableFuture<T> orTimeout(
            CompletableFuture<T> future, long timeout, TimeUnit unit) {
        java.util.Objects.requireNonNull(unit, "unit");
        if (!future.isDone()) {
            ScheduledFuture<?> timer = Delayer.SCHEDULER.schedule(
                    () -> future.completeExceptionally(new TimeoutException()), timeout, unit);
            future.whenComplete((result, ex) -> timer.cancel(false));
        }
        return future;
    }

    /**
     * Equivalent of {@code future.exceptionallyCompose(fn)} (API 34+); mirrors the
     * {@link CompletionStage#exceptionallyCompose(Function)} default implementation.
     */
    public static <T> CompletableFuture<T> exceptionallyCompose(
            CompletableFuture<T> future, Function<Throwable, ? extends CompletionStage<T>> fn) {
        // The JDK null-checks fn up front (synchronous NPE even when the future
        // has already succeeded) — match it, or hosts diverge on exactly the
        // contract this class exists to preserve.
        java.util.Objects.requireNonNull(fn, "fn");
        return future
                .handle((result, ex) -> ex == null ? future : fn.apply(ex))
                .thenCompose(Function.identity());
    }

    /** Single daemon timer thread, the same shape as the JDK's internal Delayer. */
    private static final class Delayer {
        static final ScheduledExecutorService SCHEDULER;

        static {
            ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
                Thread thread = new Thread(runnable, "myotis-future-timeout");
                thread.setDaemon(true);
                return thread;
            });
            executor.setRemoveOnCancelPolicy(true);
            SCHEDULER = executor;
        }
    }
}
