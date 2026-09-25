package io.myotis.node;

import io.myotis.api.LifecycleState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hermetic tests for the wake-on-request primitive: single-flight resume,
 * bounded holds, activity stamping, fast-fail on STOPPED — and that only a
 * WAKING stack holds (PAUSED, or RUNNING inside a warm-up window): a running
 * stack that lost readiness hands requests straight to the backend (#312).
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class WakeGateTest {

    private static final long POLL_MS = 5;

    /** A gate over the real clock, without a not-ready detail. */
    private static WakeGate gate(AtomicReference<LifecycleState> phase, BooleanSupplier ready,
                                 Runnable resume) {
        return gate(phase::get, ready, resume);
    }

    private static WakeGate gate(Supplier<LifecycleState> phase, BooleanSupplier ready,
                                 Runnable resume) {
        return new WakeGate(phase, ready, null, resume, System::currentTimeMillis, POLL_MS, "test");
    }

    private static long msSince(long t0Nanos) {
        return (System.nanoTime() - t0Nanos) / 1_000_000;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void concurrentWaitersTriggerExactlyOneResume() throws Exception {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.PAUSED);
        AtomicBoolean ready = new AtomicBoolean(false);
        AtomicInteger resumeRuns = new AtomicInteger();
        CountDownLatch resumeEntered = new CountDownLatch(1);
        CountDownLatch releaseResume = new CountDownLatch(1);
        AtomicReference<WakeGate> self = new AtomicReference<>();

        // The production order: warm-up opened before RUNNING is published, then a cold
        // stretch before the stack is ready — so a waiter released early would be caught.
        WakeGate gate = gate(phase, ready::get, () -> {
            resumeRuns.incrementAndGet();
            resumeEntered.countDown();
            try {
                releaseResume.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            self.get().beginWarmup(10_000);
            phase.set(LifecycleState.RUNNING);
            sleep(POLL_MS * 10); // RUNNING but cold
            ready.set(true);
        });
        self.set(gate);

        int waiters = 8;
        CountDownLatch done = new CountDownLatch(waiters);
        AtomicInteger answeredReady = new AtomicInteger();
        for (int i = 0; i < waiters; i++) {
            Thread t = new Thread(() -> {
                // Read readiness the instant the hold ends: a waiter let go before the
                // stack was ready must not count.
                if (gate.await(10_000) && ready.get()) answeredReady.incrementAndGet();
                done.countDown();
            });
            t.setDaemon(true);
            t.start();
        }
        // Let every waiter observe PAUSED and try to trigger a wake, then release
        // the (single) resume run.
        assertTrue(resumeEntered.await(5, TimeUnit.SECONDS));
        Thread.sleep(POLL_MS * 20);
        releaseResume.countDown();

        assertTrue(done.await(10, TimeUnit.SECONDS));
        assertEquals(1, resumeRuns.get(), "N concurrent waiters must produce exactly one resume");
        assertEquals(waiters, answeredReady.get(), "every held request is released only once ready");
    }

    @Test
    void pausedTimeoutReturnsFalseAndLaterCallRetriesTheWake() throws Exception {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.PAUSED);
        AtomicInteger resumeRuns = new AtomicInteger();

        // Resume that fails: runs, but leaves the phase PAUSED.
        WakeGate gate = gate(phase, () -> false, resumeRuns::incrementAndGet);

        assertFalse(gate.await(50), "still PAUSED at the deadline → false");
        int runsAfterFirst = resumeRuns.get();
        assertTrue(runsAfterFirst >= 1, "the failed wake ran at least once");

        // A later call finds wakeInFlight released and re-triggers the wake.
        assertFalse(gate.await(50));
        assertTrue(resumeRuns.get() > runsAfterFirst, "a later call retries the wake");
    }

    @Test
    void everyCallBumpsLastActivity() {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        long[] now = {1_000L};
        WakeGate gate = new WakeGate(phase::get, () -> true, null, () -> { },
                () -> now[0], POLL_MS, "test");

        assertEquals(0, gate.lastActivityMs());
        assertTrue(gate.await(1_000));
        assertEquals(1_000L, gate.lastActivityMs());

        now[0] = 2_000L;
        gate.poke();
        assertEquals(2_000L, gate.lastActivityMs());
    }

    @Test
    void stoppedReturnsImmediately() {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.STOPPED);
        AtomicInteger resumeRuns = new AtomicInteger();
        WakeGate gate = gate(phase, () -> true, resumeRuns::incrementAndGet);

        long t0 = System.nanoTime();
        assertFalse(gate.await(60_000));
        assertTrue(msSince(t0) < 5_000, "STOPPED must not hold the request");
        assertEquals(0, resumeRuns.get(), "STOPPED never triggers a wake");
    }

    @Test
    void runningNotReadyOutsideAWarmupIsHandedToTheBackendAtOnce() {
        // #312: a node that was serving and then lost readiness (light client catching
        // up a period, snap pool empty) must not park reads on the readiness predicate —
        // every read, eth_blockNumber included, froze for the full cap and they all
        // drained at the instant readiness came back.
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        WakeGate gate = gate(phase, () -> false, () -> { });

        long t0 = System.nanoTime();
        assertTrue(gate.await(60_000), "attempted: the backend reports why it can't answer");
        assertTrue(msSince(t0) < 5_000, "…without holding the request");
    }

    @Test
    void aPauseRacingTheReadinessCheckStillWakesTheStack() {
        // The first phase read sees RUNNING, then a pause lands before the readiness
        // check (which therefore fails). That must be handled as the pause it is — wake
        // the stack and hold — not waved through as a running stack short of readiness.
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.PAUSED);
        AtomicBoolean firstRead = new AtomicBoolean(true);
        AtomicBoolean ready = new AtomicBoolean(false);
        AtomicInteger resumeRuns = new AtomicInteger();
        AtomicReference<WakeGate> self = new AtomicReference<>();
        WakeGate gate = gate(() -> firstRead.getAndSet(false) ? LifecycleState.RUNNING : phase.get(),
                ready::get, () -> {
                    resumeRuns.incrementAndGet();
                    self.get().beginWarmup(10_000);
                    phase.set(LifecycleState.RUNNING);
                    ready.set(true);
                });
        self.set(gate);

        assertTrue(gate.await(10_000));
        assertEquals(1, resumeRuns.get(), "the racing pause triggered the wake");
        assertTrue(ready.get(), "released once the woken stack was ready");
    }

    @Test
    void aWarmupHoldsARunningStackUntilItIsReady() {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        AtomicBoolean ready = new AtomicBoolean(false);
        WakeGate gate = gate(phase, ready::get, () -> { });
        gate.beginWarmup(10_000);

        Thread warmer = new Thread(() -> {
            sleep(200);
            ready.set(true);
        });
        warmer.setDaemon(true);
        long t0 = System.nanoTime();
        warmer.start();
        assertTrue(gate.await(10_000));
        assertTrue(msSince(t0) >= 150, "held through the warm-up until ready: " + msSince(t0));
    }

    @Test
    void theWarmupWindowBoundsTheHold() {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        WakeGate gate = gate(phase, () -> false, () -> { });
        gate.beginWarmup(100);

        long t0 = System.nanoTime();
        assertTrue(gate.await(60_000), "the window ran out: attempt the read");
        long ms = msSince(t0);
        assertTrue(ms >= 80 && ms < 5_000, "held for the window, not the cap: " + ms + " ms");
    }

    @Test
    void readinessClosesTheWarmup() {
        // Once a warm-up is seen to complete, a later readiness loss belongs to a running
        // node: not held, although the window's time hasn't run out.
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        AtomicBoolean ready = new AtomicBoolean(true);
        WakeGate gate = gate(phase, ready::get, () -> { });
        gate.beginWarmup(10_000);
        assertTrue(gate.await(10_000));

        ready.set(false);
        long t0 = System.nanoTime();
        assertTrue(gate.await(10_000));
        assertTrue(msSince(t0) < 5_000, "no hold once the node has warmed up");
    }

    @Test
    void aWarmupNobodyWaitedOnStillEndsAtReadiness() {
        // The stack gets ready with no request around to see it, then loses readiness later
        // in the window. That later read must not be held: the window closed at the first
        // readiness, observed by a request or not — otherwise the #312 freeze comes back,
        // bounded by the window instead of the cap.
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        AtomicBoolean ready = new AtomicBoolean(true);
        WakeGate gate = gate(phase, ready::get, () -> { });
        gate.beginWarmup(10_000);
        long give = System.nanoTime() + 5_000_000_000L;
        while (gate.warmingUp() && System.nanoTime() - give < 0) sleep(POLL_MS);
        assertFalse(gate.warmingUp(), "the watcher closed the window at readiness");

        ready.set(false);
        long t0 = System.nanoTime();
        assertTrue(gate.await(10_000));
        assertTrue(msSince(t0) < 5_000, "a later readiness loss is not held");
    }

    @Test
    void aWakeHoldsThroughTheColdStartThatFollowsIt() {
        // The production order: the resume opens the warm-up BEFORE it publishes RUNNING,
        // then the stack sits RUNNING-but-cold (re-anchoring, re-dialing) for a while. The
        // request that triggered the wake must stay held through that, not be released
        // into a cold backend the moment the phase flips.
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.PAUSED);
        AtomicBoolean ready = new AtomicBoolean(false);
        AtomicReference<WakeGate> self = new AtomicReference<>();
        WakeGate gate = gate(phase, ready::get, () -> {
            self.get().beginWarmup(10_000);
            phase.set(LifecycleState.RUNNING);
            sleep(200); // RUNNING but cold
            ready.set(true);
        });
        self.set(gate);

        long t0 = System.nanoTime();
        assertTrue(gate.await(10_000));
        assertTrue(ready.get(), "released only once the woken stack was ready");
        assertTrue(msSince(t0) >= 150, "held through the cold start: " + msSince(t0) + " ms");
    }

    @Test
    void runningButStillWarmingAtTheCapReturnsTrue() {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        WakeGate gate = gate(phase, () -> false, () -> { });
        gate.beginWarmup(2_000);

        // Warming but never ready: at the cap the request is handed to the backend
        // anyway (it produces its own precise bounded errors).
        assertTrue(gate.await(50));
    }

    @Test
    void aThrowingNotReadyDetailNeverBreaksAHold() {
        // The slow-hold WARN asks for the not-ready detail; a diagnostics failure (e.g.
        // an unreadable native status) must stay inside the log line.
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        WakeGate gate = new WakeGate(phase::get, () -> false,
                () -> { throw new IllegalStateException("status unreadable"); },
                () -> { }, System::currentTimeMillis, POLL_MS, "test");
        gate.beginWarmup(5_000);

        long t0 = System.nanoTime();
        assertTrue(gate.await(WakeGate.SLOW_HOLD_WARN_MS + 300));
        assertTrue(msSince(t0) >= WakeGate.SLOW_HOLD_WARN_MS, "held past the WARN point");
    }
}
