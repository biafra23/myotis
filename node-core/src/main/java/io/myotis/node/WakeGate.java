package io.myotis.node;

import io.myotis.api.LifecycleState;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The wake-on-request primitive behind {@link ChainStack#awaitReadyForReads}:
 * stamps host-visible activity, triggers a single-flight asynchronous resume
 * when the stack is {@code PAUSED}, and parks the calling (request) thread
 * until the stack can answer verified reads or a deadline passes.
 *
 * <p>Extracted from {@code ChainStack} so the wait/single-flight behavior is
 * hermetically testable — every dependency (phase, readiness, resume action,
 * clock) is injected.
 *
 * <p>Public (not package-private) because the Rust engine's Java shim
 * ({@code io.myotis.engines.RustChainHandle}) reuses the same wake-on-request
 * primitive over its native lifecycle, so the two engines can't drift on the
 * hold/single-flight semantics.
 */
public final class WakeGate {

    private final Supplier<LifecycleState> phase;
    private final BooleanSupplier ready;
    private final Runnable resume;
    private final LongSupplier clock;
    private final long pollMs;
    private final String wakeThreadName;

    private final AtomicBoolean wakeInFlight = new AtomicBoolean(false);
    private final AtomicLong lastActivityMs = new AtomicLong(0);

    /**
     * @param phase          live lifecycle state of the guarded stack
     * @param ready          true when verified reads are answerable (only consulted while RUNNING)
     * @param resume         the blocking resume action; run on a fresh daemon thread, single-flight
     * @param clock          wall-clock epoch-millis source for activity stamping (injected for
     *                       tests); the wait DEADLINE uses monotonic {@code System.nanoTime}
     * @param pollMs         wait-loop poll interval
     * @param wakeThreadName name for the spawned resume thread
     */
    public WakeGate(Supplier<LifecycleState> phase, BooleanSupplier ready, Runnable resume,
                    LongSupplier clock, long pollMs, String wakeThreadName) {
        this.phase = phase;
        this.ready = ready;
        this.resume = resume;
        this.clock = clock;
        this.pollMs = pollMs;
        this.wakeThreadName = wakeThreadName;
    }

    /**
     * Note activity, kick a wake if paused, and block until the stack is ready
     * for verified reads or {@code capMs} elapses.
     *
     * @return {@code true} when reads should be attempted: the stack is ready, or
     *         it is {@code RUNNING} but still cold at the deadline (the backend
     *         produces its own precise bounded errors). {@code false} when the
     *         stack is {@code STOPPED}, still {@code PAUSED} at the deadline
     *         (resume kept failing), or the wait was interrupted.
     */
    public boolean await(long capMs) {
        noteActivity();
        // Monotonic deadline (nanoTime, overflow-safe compare): capMs is a DURATION, so an
        // NTP / manual wall-clock step must not extend or prematurely expire the hold. The
        // injected wall-clock `clock` is used only for activity stamping (noteActivity),
        // which the host idle timer compares against its own wall clock.
        long deadlineNanos = System.nanoTime() + capMs * 1_000_000L;
        while (true) {
            LifecycleState p = phase.get();
            if (p == LifecycleState.STOPPED) return false;
            if (p == LifecycleState.PAUSED) triggerWake();
            if (p == LifecycleState.RUNNING && ready.getAsBoolean()) return true;
            if (System.nanoTime() - deadlineNanos >= 0) return p == LifecycleState.RUNNING;
            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /** Note activity and kick a wake if paused, without blocking (status probes). */
    public void poke() {
        noteActivity();
        if (phase.get() == LifecycleState.PAUSED) triggerWake();
    }

    public void noteActivity() {
        lastActivityMs.set(clock.getAsLong());
    }

    /** Epoch millis of the last {@link #await}/{@link #poke}; 0 if none yet. */
    public long lastActivityMs() {
        return lastActivityMs.get();
    }

    /**
     * Single-flight: N concurrent waiters produce one resume run. The flag is
     * released when the run finishes, so a failed resume is retried by whichever
     * waiter polls next.
     */
    private void triggerWake() {
        if (!wakeInFlight.compareAndSet(false, true)) return;
        Thread t = new Thread(() -> {
            try {
                resume.run();
            } finally {
                wakeInFlight.set(false);
            }
        }, wakeThreadName);
        t.setDaemon(true);
        t.start();
    }
}
