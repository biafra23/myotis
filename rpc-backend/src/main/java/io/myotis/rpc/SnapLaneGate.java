package io.myotis.rpc;

import java.util.function.IntSupplier;

/**
 * Caps how much of the shared snap-peer pool a HEAVY-lane EVM execution (a big token
 * sweep / multicall) may use <em>concurrently</em>, so its fan-out can't starve the
 * gating calls (nonce / balance / fee) that draw from the same peers.
 *
 * <p>The two EVM lanes already run on separate thread pools (small vs heavy), but threads
 * aren't the contended resource — the thin snap-peer set is. Both lanes' fetches issue
 * {@code GetTrieNodes} / range requests to the same {@code activeSnapHandlers()}, with no
 * reservation, so a sweep firing dozens of concurrent fetches queues the gating calls
 * behind it at the network level. This gate fixes that without rejecting anything: a
 * heavy-lane snap request must hold a permit, and the permit count is <strong>half the
 * live snap peers</strong> (recomputed each acquire), leaving the other half free for the
 * small/interactive calls, which never acquire. Heavy calls then run to genuine
 * completion / OutOfGas / timeout — just never more than their share of peers at once.
 *
 * <p>Lane is a per-thread flag set on the EVM pool thread (heavy pool vs the reserved
 * small-call thread). Every snap request is issued synchronously on that thread (the
 * prefetch waves and per-item fetches all call the oracle in-thread before awaiting), so
 * {@link #acquireIfHeavy} sees the right lane at issue time and {@link #release} runs on
 * the request's completion. The wait is bounded ({@code maxWaitMs}) purely as a
 * deadlock-safety net — permits always free as in-flight requests complete on the network
 * threads, independent of the blocked EVM thread.
 */
public final class SnapLaneGate {

    private static final ThreadLocal<Boolean> HEAVY = new ThreadLocal<>();

    private final IntSupplier liveSnapPeers;
    private final long maxWaitMs;
    private final Object lock = new Object();
    private int heavyInFlight;

    public SnapLaneGate(IntSupplier liveSnapPeers, long maxWaitMs) {
        this.liveSnapPeers = liveSnapPeers;
        this.maxWaitMs = maxWaitMs;
    }

    /** Mark the current EVM-pool thread's lane for the duration of a task. */
    static void enterLane(boolean heavy) {
        if (heavy) HEAVY.set(Boolean.TRUE); else HEAVY.remove();
    }

    /** Clear the lane flag (call in a finally when the EVM task ends). */
    static void clearLane() {
        HEAVY.remove();
    }

    static boolean isHeavyThread() {
        return Boolean.TRUE.equals(HEAVY.get());
    }

    /** Heavy lane may use at most half the live snap peers; min 1 so it never fully stalls
     *  when the pool is tiny (a single peer means no reservation is possible anyway). */
    private int heavyLimit() {
        return Math.max(1, liveSnapPeers.getAsInt() / 2);
    }

    /**
     * If the calling thread is a heavy lane, block until a heavy permit is free (bounded by
     * {@code maxWaitMs}), then take it. Returns {@code true} iff a permit was taken and the
     * caller must later {@link #release()} exactly once. Small-lane threads return
     * {@code false} immediately — they are never throttled.
     */
    public boolean acquireIfHeavy() {
        if (!isHeavyThread()) return false;
        synchronized (lock) {
            long deadlineNanos = System.nanoTime() + maxWaitMs * 1_000_000L;
            while (heavyInFlight >= heavyLimit()) {
                long remMs = (deadlineNanos - System.nanoTime()) / 1_000_000L;
                if (remMs <= 0) break;   // soft cap: proceed rather than stall the EVM thread
                try {
                    lock.wait(remMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            heavyInFlight++;
            return true;
        }
    }

    /** Release a permit taken by {@link #acquireIfHeavy()} (which returned true). */
    public void release() {
        synchronized (lock) {
            if (heavyInFlight > 0) heavyInFlight--;
            lock.notifyAll();
        }
    }

    /** Current in-flight heavy permit count (for tests / diagnostics). */
    int inFlight() {
        synchronized (lock) { return heavyInFlight; }
    }
}
