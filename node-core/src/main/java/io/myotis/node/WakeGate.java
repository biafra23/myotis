package io.myotis.node;

import io.myotis.api.LifecycleState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The wake-on-request primitive behind {@link ChainStack#awaitReadyForReads}:
 * stamps host-visible activity, triggers a single-flight asynchronous resume
 * when the stack is {@code PAUSED}, and parks the calling (request) thread
 * until the stack can answer verified reads or a deadline passes.
 *
 * <p><b>Only a WAKING stack holds requests.</b> A request is parked while the
 * stack is {@code PAUSED} (the wake is in flight), or {@code RUNNING} but not
 * yet ready inside a <em>warm-up window</em> — opened by every (re)entry into
 * {@code RUNNING} ({@link #beginWarmup}) and closed as soon as the stack is first
 * ready (a watcher polls through the warm-up, so that doesn't depend on a request
 * being there to see it), or when the window elapses. That is the climb the hold
 * exists for: a start or a wake re-anchoring the light client and re-dialing snap
 * peers, seconds away from answering. A {@code RUNNING} stack outside a warm-up
 * is never held, ready or not: a node that WAS serving and then lost readiness
 * (the light client catching up a sync-committee period, the snap pool
 * momentarily empty) hands the request straight to the backend, which answers or
 * fails with its own precise, bounded error. Holding those parked every verified
 * read — {@code eth_blockNumber} included — on one shared readiness predicate for
 * the full cap and released them all at the same instant: wallets with a 10 s
 * timeout reported the node offline for minutes while every request eventually
 * "succeeded" (#312).
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

    private static final Logger log = LoggerFactory.getLogger(WakeGate.class);

    /** A hold still parked after this long is logged once at WARN, with why the
     *  stack isn't ready — the "which phase is this request stuck in" half of the
     *  #312 instrumentation (the router's slow-call WARN names the request). */
    static final long SLOW_HOLD_WARN_MS = 1_000L;

    private final Supplier<LifecycleState> phase;
    private final BooleanSupplier ready;
    private final Supplier<String> notReadyDetail;
    private final Runnable resume;
    private final LongSupplier clock;
    private final long pollMs;
    private final String name;

    private final AtomicBoolean wakeInFlight = new AtomicBoolean(false);
    private final AtomicLong lastActivityMs = new AtomicLong(0);

    /** The open warm-up window, or null. A holder object rather than a bare
     *  deadline: closing it is a CAS on the exact window read, so neither a ready
     *  poll nor a finishing watcher can close a newer window a racing resume
     *  opened — and no nanoTime value has to double as a "none" sentinel (any
     *  long is a valid reading). */
    private final AtomicReference<Warmup> warmup = new AtomicReference<>();

    private record Warmup(long deadlineNanos) {}

    /**
     * @param phase          live lifecycle state of the guarded stack
     * @param ready          true when verified reads are answerable (only consulted while RUNNING)
     * @param notReadyDetail short reason the stack isn't ready yet (e.g. its beacon state and
     *                       snap-peer count) for the slow-hold WARN; null — or a supplier that
     *                       throws — just leaves the detail out
     * @param resume         the blocking resume action; run on a fresh daemon thread, single-flight
     * @param clock          wall-clock epoch-millis source for activity stamping (injected for
     *                       tests); the wait DEADLINE uses monotonic {@code System.nanoTime}
     * @param pollMs         wait-loop poll interval
     * @param name           the guarded network, for logs; the resume thread is
     *                       {@code wake-resume-<name>}
     */
    public WakeGate(Supplier<LifecycleState> phase, BooleanSupplier ready,
                    Supplier<String> notReadyDetail, Runnable resume,
                    LongSupplier clock, long pollMs, String name) {
        this.phase = phase;
        this.ready = ready;
        this.notReadyDetail = notReadyDetail;
        this.resume = resume;
        this.clock = clock;
        this.pollMs = pollMs;
        this.name = name;
    }

    /**
     * Open (or restart) the warm-up window: for the next {@code windowMs}, a request
     * that finds the stack RUNNING but not yet ready is held until it is (each hold
     * still bounded by its own cap). Call on every (re)entry into RUNNING — start and
     * resume, whatever woke the stack — and BEFORE that RUNNING can be observed: a
     * waiter polling between the flip and the open would see a running, unready
     * stack with no warm-up and be released into a cold backend.
     */
    public void beginWarmup(long windowMs) {
        Warmup w = new Warmup(System.nanoTime() + windowMs * 1_000_000L);
        warmup.set(w);
        // End the window the moment the stack is first ready, whether or not a request is
        // there to see it: a window no poll saw complete would stay open, and a readiness
        // blip later in it (a snap-pool reshuffle after a resume) would park every read until
        // it ran out — the #312 freeze again, bounded by the window instead of the cap.
        Thread t = new Thread(() -> watchWarmup(w), "wake-warmup-" + name);
        t.setDaemon(true);
        t.start();
    }

    /** Poll through one warm-up window and close it at the stack's first readiness, when
     *  it stops, or when the window runs out; exits early once a newer window replaces it. */
    private void watchWarmup(Warmup w) {
        while (warmup.get() == w && System.nanoTime() - w.deadlineNanos() < 0) {
            try {
                LifecycleState p = phase.get();
                if (p == LifecycleState.STOPPED) break; // nothing holds; a later start reopens
                if (p == LifecycleState.RUNNING && ready.getAsBoolean()) break;
            } catch (RuntimeException e) {
                // An unreadable status is "not ready yet" — never a dead watcher.
            }
            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        warmup.compareAndSet(w, null); // a no-op once superseded
    }

    /** Whether a warm-up window is open right now (test seam). */
    boolean warmingUp() {
        Warmup w = warmup.get();
        return w != null && System.nanoTime() - w.deadlineNanos() < 0;
    }

    /**
     * Note activity, kick a wake if paused, and — only while the stack is waking (see
     * the class doc) — block until it is ready for verified reads or {@code capMs}
     * elapses.
     *
     * @return {@code true} when reads should be attempted: the stack is ready; it is
     *         {@code RUNNING} outside a warm-up (the backend answers, or produces its
     *         own precise bounded errors); or it is {@code RUNNING} but still warming
     *         up at the deadline. {@code false} when the stack is {@code STOPPED},
     *         still {@code PAUSED} at the deadline (resume kept failing), or the wait
     *         was interrupted.
     */
    public boolean await(long capMs) {
        noteActivity();
        // Monotonic deadline (nanoTime, overflow-safe compare): capMs is a DURATION, so an
        // NTP / manual wall-clock step must not extend or prematurely expire the hold. The
        // injected wall-clock `clock` is used only for activity stamping (noteActivity),
        // which the host idle timer compares against its own wall clock.
        long startNanos = System.nanoTime();
        long deadlineNanos = startNanos + capMs * 1_000_000L;
        boolean warned = false;
        while (true) {
            LifecycleState p = phase.get();
            if (p == LifecycleState.STOPPED) return released(warned, startNanos, "stopped", false);
            if (p == LifecycleState.PAUSED) triggerWake();
            if (p == LifecycleState.RUNNING) {
                // Read the window BEFORE readiness, so a ready poll closes exactly the
                // window it saw (a resume racing in after it has opened a fresh one).
                Warmup w = warmup.get();
                if (ready.getAsBoolean()) {
                    // Warmed up: from here on a readiness loss is the backend's to report.
                    if (w != null) warmup.compareAndSet(w, null);
                    return released(warned, startNanos, "ready", true);
                }
                if (w == null || System.nanoTime() - w.deadlineNanos() >= 0) {
                    if (w != null) warmup.compareAndSet(w, null);
                    // A pause (or stop) that landed between the phase read and the
                    // readiness check is handled as one — re-poll, which wakes a PAUSED
                    // stack — not waved through as a running stack short of readiness.
                    if (phase.get() != LifecycleState.RUNNING) continue;
                    // Not waking: a running stack that lost readiness (or whose warm-up
                    // ran out). Hand the request to the backend now instead of parking it
                    // on a predicate that can stay false for minutes (#312).
                    return released(warned, startNanos, "not warming up", true);
                }
            }
            long now = System.nanoTime();
            if (now - deadlineNanos >= 0) {
                return released(warned, startNanos, "cap reached", p == LifecycleState.RUNNING);
            }
            if (!warned && now - startNanos >= SLOW_HOLD_WARN_MS * 1_000_000L) {
                warned = true;
                log.warn("[wake-gate:{}] verified read held {} ms: {}; holding up to {} s",
                        name, (now - startNanos) / 1_000_000L, holdReason(p), capMs / 1000);
            }
            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return released(warned, startNanos, "interrupted", false);
            }
            // Still parked: this request IS ongoing activity. Re-stamp every poll so a
            // wake-hold longer than the host's idle window can't leave the activity
            // clock stale and let the idle controller re-pause the stack under the
            // parked request (a wake/pause ping-pong until the cap expires).
            noteActivity();
        }
    }

    /** The single exit of {@link #await}: a hold long enough to have been WARNed about
     *  also logs how it ended, so a stall reads as a bounded episode in the log. */
    private boolean released(boolean warned, long startNanos, String how, boolean attempt) {
        if (warned) {
            log.info("[wake-gate:{}] verified read released after {} ms ({})",
                    name, (System.nanoTime() - startNanos) / 1_000_000L, how);
        }
        return attempt;
    }

    /** Why a hold is still parked, for the slow-hold WARN. */
    private String holdReason(LifecycleState p) {
        String why = p == LifecycleState.PAUSED
                ? "stack PAUSED, wake in progress"
                : "stack RUNNING but still warming up after a start/wake";
        if (notReadyDetail == null) return why;
        try {
            String detail = notReadyDetail.get();
            return detail == null || detail.isBlank() ? why : why + " (" + detail + ")";
        } catch (RuntimeException e) {
            return why; // diagnostics must never break the hold itself
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
        }, "wake-resume-" + name);
        t.setDaemon(true);
        t.start();
    }
}
