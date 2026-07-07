package io.myotis.node;

import io.myotis.api.LifecycleState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hermetic tests for the wake-on-request primitive: single-flight resume,
 * bounded holds, activity stamping, and fast-fail on STOPPED.
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class WakeGateTest {

    private static final long POLL_MS = 5;

    @Test
    void concurrentWaitersTriggerExactlyOneResume() throws Exception {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.PAUSED);
        AtomicBoolean ready = new AtomicBoolean(false);
        AtomicInteger resumeRuns = new AtomicInteger();
        CountDownLatch resumeEntered = new CountDownLatch(1);
        CountDownLatch releaseResume = new CountDownLatch(1);

        WakeGate gate = new WakeGate(phase::get, ready::get, () -> {
            resumeRuns.incrementAndGet();
            resumeEntered.countDown();
            try {
                releaseResume.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            phase.set(LifecycleState.RUNNING);
            ready.set(true);
        }, System::currentTimeMillis, POLL_MS, "test-wake");

        int waiters = 8;
        CountDownLatch done = new CountDownLatch(waiters);
        AtomicInteger successes = new AtomicInteger();
        for (int i = 0; i < waiters; i++) {
            Thread t = new Thread(() -> {
                if (gate.await(10_000)) successes.incrementAndGet();
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
        assertEquals(waiters, successes.get(), "all held requests answer after the wake");
    }

    @Test
    void pausedTimeoutReturnsFalseAndLaterCallRetriesTheWake() throws Exception {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.PAUSED);
        AtomicInteger resumeRuns = new AtomicInteger();

        // Resume that fails: runs, but leaves the phase PAUSED.
        WakeGate gate = new WakeGate(phase::get, () -> false, resumeRuns::incrementAndGet,
                System::currentTimeMillis, POLL_MS, "test-wake");

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
        WakeGate gate = new WakeGate(phase::get, () -> true, () -> { },
                () -> now[0], POLL_MS, "test-wake");

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
        WakeGate gate = new WakeGate(phase::get, () -> true, resumeRuns::incrementAndGet,
                System::currentTimeMillis, POLL_MS, "test-wake");

        long t0 = System.nanoTime();
        assertFalse(gate.await(60_000));
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(elapsedMs < 5_000, "STOPPED must not hold the request");
        assertEquals(0, resumeRuns.get(), "STOPPED never triggers a wake");
    }

    @Test
    void runningButColdAtDeadlineReturnsTrue() {
        AtomicReference<LifecycleState> phase = new AtomicReference<>(LifecycleState.RUNNING);
        WakeGate gate = new WakeGate(phase::get, () -> false, () -> { },
                System::currentTimeMillis, POLL_MS, "test-wake");

        // RUNNING but never ready: at the cap the request is handed to the backend
        // anyway (it produces its own precise bounded errors).
        assertTrue(gate.await(50));
    }
}
